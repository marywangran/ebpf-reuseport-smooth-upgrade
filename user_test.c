#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

#define MAX_WORKERS 10
#define SIZE_MAP_NAME "size_map"
#define REFCNT_MAP_NAME "refcnt_map"
#define SESSION_MAP_NAME "session_map"
#define REDIRECT_MAP_NAME "redirect_map"

int g_curr_idx = 0, g_curr_pos = 0；

void reload(int size_map_fd, int session_map_fd);
void session_exit(int refcnt_map_fd, int session_map_fd, int size_map_fd, int redirect_map_fd, int socket_idx);
void session_value_exit(int refcnt_map_fd, int session_map_fd, int size_map_fd, int redirect_map_fd, int curr_value);
int init_map_fd(struct bpf_object *obj, const char *map_name)
{
    int map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
    if (map_fd < 0) {
        fprintf(stderr, "Error finding eBPF map: %s\n", map_name);
    }
    return map_fd;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog = NULL;
    int err = 0;

    obj = bpf_object__open_file("reuseport_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error loading eBPF program: %d\n", err);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(obj, "your_prog_name");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return -1;
    }

    int size_map_fd = init_map_fd(obj, SIZE_MAP_NAME);
    int refcnt_map_fd = init_map_fd(obj, REFCNT_MAP_NAME);
    int session_map_fd = init_map_fd(obj, SESSION_MAP_NAME);
    int redirect_map_fd = init_map_fd(obj, REDIRECT_MAP_NAME);

    if (size_map_fd < 0 || refcnt_map_fd < 0 || session_map_fd < 0 || redirect_map_fd < 0) {
        bpf_object__close(obj);
        return 1;
    }

    // 模拟 reload
    reload(size_map_fd, session_map_fd);

    // 模拟 session 退出
    session_exit(refcnt_map_fd, session_map_fd, size_map_fd, redirect_map_fd, 0);

    // 模拟 session 中 value 为 curr_value 的 socket 退出操作
    session_value_exit(refcnt_map_fd, session_map_fd, size_map_fd, redirect_map_fd, 5);

    bpf_object__close(obj);
    return 0;
}

// reload
void reload(int size_map_fd, int session_map_fd)
{
    // 创建 MAX_WORKERS 个 reuseport socket
    for (int i = 0; i < MAX_WORKERS; i++) {
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("socket creation failed");
            continue;
        }
        int optval = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
            perror("setsockopt SO_REUSEPORT failed");
            close(sockfd);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(8080);

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind failed");
            close(sockfd);
            continue;
        }

        if (listen(sockfd, 5) < 0) {
            perror("listen failed");
            close(sockfd);
            continue;
        }
	bpf_map_update_elem(redirect_map_fd, &g_curr_pos, &g_curr_idx, BPF_EXIST);
	g_curr_pos += 1；
	g_curr_idx += 1；
        // 基本假设 socket 会追加到 group 最后，自动递增索引，由新 session 存储到 session_map 中
        // 递增 size_map 中 size 项
        __u32 key = 0;
        __u32 *size;
        if (bpf_map_lookup_elem(size_map_fd, &key, &size) == 0) {
            __sync_fetch_and_add(size, MAX_WORKERS);
        }
    }
}

// session 退出
void session_exit(int refcnt_map_fd, int session_map_fd, int size_map_fd, int redirect_map_fd, int socket_idx)
{
    __u32 key = socket_idx;
    __u32 *refcnt;
    if (bpf_map_lookup_elem(refcnt_map_fd, &key, &refcnt) == 0) {
        __sync_fetch_and_sub(refcnt, 1);
        if (*refcnt == 0) {
            // socket 退出
           session_value_exit(refcnt_map_fd, session_map_fd, size_map_fd, redirect_map_fd, key);
        }
    }
}

// session_map 中 value 为 curr_value 的 socket 退出操作
void session_value_exit(int refcnt_map_fd, int session_map_fd, int size_map_fd, int redirect_map_fd, int curr_value)
{
    __u32 size_key = 0;
    __u32 *size;
    if (bpf_map_lookup_elem(size_map_fd, &size_key, &size) != 0) {
        return;
    }

    // 做一致性 hash，遍历 session_map
    int max_value = 0, pos = -1;
    for (__u32 key = 0; key < *size; key++) {
        __u32 *value;
        if (bpf_map_lookup_elem(redirect_map_fd, &key, &value) == 0) {
		    if (*value > max_value) {
			    max_value = *value;
		    }
        }
	    if (*value == curr_value) {
		    pos = key;
	    }
    }
    bpf_map_update_elem(redirect_map_fd, &pos, &max_value, BPF_EXIST);

    g_curr_pos -= 1；
    g_curr_idx -= 1；
    if (pos < *size - MAX_WORKERS) {
        // 递减 size
        __sync_fetch_and_sub(size, 1);
	// TODO，必须！for-each session map，value 递减
    } else {
        // 新建 worker socket
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("socket creation failed");
            return;
        }


        int optval = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
            perror("setsockopt SO_REUSEPORT failed");
            close(sockfd);
            return;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(8080);

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind failed");
            close(sockfd);
            return;
        }
	// TODO   必须追踪 socket 创建顺序，并更新 redirect map，否则无法运行
	g_curr_idx += 1；
	bpf_map_update_elem(redirect_map_fd, &pos, &g_curr_idx, BPF_EXIST);
    }
}
