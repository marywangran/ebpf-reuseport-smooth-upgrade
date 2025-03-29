## reuseport socket worker 的热升级

比如现有 socket idx：0，1，2，3，如果 reload，新建 4，5，6，7，为了让 0，1，2，3 的所有 session 自然流失掉，新 session 只从 curr_size( = 8) 的后 4 个中选择，如果再 reload，则从 8，9，10，11 中接收新 session，让 0～7 自然流失掉，以此类推。
如果有 worker socket 的 session 数量变成 0，退出时要更新所有 idx 大于它的 entry，做好一致性映射（用一个 redirect map）。

- before reload：什么都不做
- reload：创建 MAX_WORKERS 个 worker reuseport socket
- after reload：递增 size_map 中唯一的 size 项：__sync_fetch_and_add(size, MAX_WORKERS)

- session 退出（由 worker 调用）：递减 refcnt_map 对应 socket_idx 引用计数，递减到 0，socket 退出

- session_map 中 value 为 curr_value 的 socket 退出（由 worker 调用）【该步骤可能会丢包，串包】：做一致性 hash，更新 redirect map，若 sk_pos < size - MAX_WORKERS，递减 size，否则，只新建 worker socket。
