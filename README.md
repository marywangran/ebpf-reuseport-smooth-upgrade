
- before reload：什么都不做
- reload：创建 MAX_WORKERS 个 worker reuseport socket
- after reload：递增 size_map 中唯一的 size 项：__sync_fetch_and_add(size, MAX_WORKERS)

- session 退出（由 worker 调用）：递减 refcnt_map 对应 socket_idx 引用计数，递减到 0，socket 退出

- socket 退出（由 worker 调用）【该步骤可能会丢包，串包】：做一致性 hash，遍历 session_map，所有 idx > curr_idx && idx < size - MAX_WORKERS 的，value -= 1，递减 size：size -= 1，若 idx <= size - MAX_WORKERS，则 value -= 1，新建 worker，不递减 size
