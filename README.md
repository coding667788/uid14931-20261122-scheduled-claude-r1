# mapping_guard — 虚拟设备换挂安全审计器

`mapping_guard` 是一个**纯逻辑**安全审计器：它读取虚构的页区间、设备队列和逻辑
事件，不访问任何硬件、驱动或真实内存。它回答两类问题：

1. **apply / inspect**：给定一条只增的逻辑事件流，什么时候才允许把宿主页从一个
   租户交接给另一个租户？交接必须在同一个 SQLite 事务内核对哪些条件？事后按提交号
   审计时，每段区间还缺哪些失效证据？
2. **schedule**：给定固定的目标页交接清单和候选维护命令，选出一组**事先固定**的
   维护命令与执行时段，使基线和每个允许的单队列故障情形都能在各期限前安全交接。

仅依赖 Python 3.12 标准库（含 `sqlite3`），无第三方包。

---

## 1. 运行方式

在仓库根目录（本 README 所在目录）执行：

```bash
# 持久化命令（apply / inspect 需要 --db）
python -m mapping_guard apply    CASE.json --db DB.sqlite
python -m mapping_guard inspect  QUERY.json --db DB.sqlite

# 纯计算命令
python -m mapping_guard schedule CASE.json
```

- 所有输出都是确定性的 UTF-8 JSON（`ensure_ascii=False`、固定键顺序、无时间戳、
  无随机数），同一输入两次运行逐字节相同。
- 成功退出码 `0`；结构错误退出码 `2`；安全规则错误退出码 `3`；命令行用法错误
  退出码 `4`。错误统一为 `{"ok": false, "error": {field, code, message}}`。
- 地址空间上界为 `2^52`，左闭右开 `[start, end)`。**持久层从不按单页展开**，
  只存区间行。

运行测试（含独立穷举核对与双进程并发验证）：

```bash
python -m unittest discover -s tests -v
```

重新生成全部确定性合成场景：

```bash
python cases/generate_cases.py
```

---

## 2. 核心规则模型

### 2.1 身份与代次

| 概念 | 含义 |
|---|---|
| `qi` | 队列身份 `(device, slot, queue_no)`，热插拔可复用槽位与队列编号 |
| `instance` | 队列实例代次，单调递增、**永不复用**；同一活动实例可追加不同映射代次的授权 |
| `gen` | 设备源映射表条目代次 |
| 段（segment） | 一条半开区间映射，带属主、代次、权限和有效位；按区间粒度永久保存 |

`bind` 事件同时是一份**授权**：它把设备实例、队列、租户映射代次、页区间与读写权限
绑定在一起。之后的 `map` / `register_command` / `cache_publish` 都必须能找到覆盖
目标区间的授权，否则以 `unauthorized` 拒绝。

### 2.2 映射与只读缓存

- 映射允许**大区间覆盖**。对子区间重映射时，区间两侧的旧有效映射原样保留，被替换
  的中间部分以 `removed_by` 记录触发事件（即 `inspect` 报告的触发证据）。
- 每个设备有一张源映射表和若干只读缓存模型。缓存条目只服从**属于自己队列实例、
  映射代次且区间相交**的失效确认：
  - 旧实例的确认不能抵消新实例的缓存（按 `(qi, instance, gen)` 匹配）；
  - 单次确认可只覆盖部分区间；多份确认自动合并；
  - 允许延迟、重放、重复、相互交叠的确认；无匹配实例/代次或区间无条目的确认被
    标记为无效（`ack_ignored`），不产生任何失效效果。
- 缓存条目在“未被同设备同代次有效映射覆盖、且尚未被确认”的地址上构成**残留**。

### 2.3 在途引用与可交接条件

源映射被撤销后的旧条目仍是**潜在在途引用**，直到同时满足：

1. 相应队列完成本区间的失效确认（缓存残留清零）；
2. 撤销前已登记的命令全部拿到 `completed` 或 `cancelled` 回执。

- **撤销后不得补登记引用**：`register_command` / `cache_publish` 落在已无有效同代次
  映射的地址上时，分别以 `registration_after_revoke` /
  `publish_without_mapping` 拒绝。
- 旧代命令的完成回执只是记账，不会借当前页归属继续完成，也不会清除缓存证据。
- 宿主页只有在**所有相关设备实例和队列**的引用归零后才能交给另一租户；其它设备仍
  有效映射该页时以 `other_device_holds_page` 拒绝。

### 2.4 交接事务（apply）

`handoff_request` 登记预期源版本、原/新属主和左闭右开交接窗口。处理一批事件时：

1. 先在事务外做测试屏障同步（仅测试钩子，见第 5 节），随后开启
   `BEGIN IMMEDIATE` 拿写锁；
2. 在**同一个 SQLite 事务内**核对：
   - 预期 `expected_source_version` 与当前源版本完全一致，否则 `version_conflict`；
   - 窗口可由该设备最近映射史解释且属主全部为 `from_owner`；
   - 无其它设备有效持有窗口内页面；
   - 窗口内缓存残留与未回执的撤销前命令全部归零，否则 `outstanding_references`；
   - `new_gen` 未在该设备上使用过；
3. 核对通过后，在同一事务内写入完整页区间切换（新代次段）与回执行；
4. 任一步失败则整批回滚——**部分确认和排空证据可以暂存，但失败批次不留下任何
   部分写入**。

幂等与冲突：

- 相同 `request_id` 且**内容哈希相同**的重复请求返回原回执
  （`idempotent_replay`），交接表保持一行；
- 相同 `request_id` 但内容不同 → 整批拒绝（`handoff_conflict`）；
- 并发下唯一键竞争被翻译成 `concurrent_commit_conflict`，事务回滚。

内容哈希仅由交接语义字段计算（`request_id, device, from_owner, to_owner,
expected_source_version, new_gen, range, perms`），与事件 `id` 无关。

### 2.5 历史视图（inspect）

`inspect` 从只增事件日志重放到指定 `commit`，因此看到的就是该提交时刻的合法状态：

- `legal_ownership_at_commit`：该提交时刻仍有效的映射段；
- `handoffs_visible_at_commit`：截至该提交可见的交接；
- `blocking_queues`：按 `(设备, 队列, 实例)` 分组的未完成失效证据，每组给出
  - `minimal_blocking_range`：合并后的最小阻塞区间（不按页展开）；
  - `trigger_events`：使相应映射失效的撤销/重映射事件；
  - `missing_evidence`：逐条缓存残留或未回执命令（含种类、代次、区间、触发事件）。
- 请求提交号超过当前头时返回 `commit_ahead_of_head`。

---

## 3. 输入/输出接口

### 3.1 apply 输入 `CASE.json`

```json
{
  "case_id": "string",
  "events": [ { "id": "string", "type": "<类型>", "...": "类型相关字段" } ]
}
```

事件类型与必填字段（`perms` 可选，取值 `["r"]`、`["w"]`、`["r","w"]`）：

| type | 必填字段 |
|---|---|
| `bind` | device, slot, queue_no, instance, gen, range |
| `unbind` | device, slot, queue_no, instance |
| `map` | device, slot, queue_no, instance, gen, owner, range |
| `revoke` | device, gen, range |
| `register_command` | device, slot, queue_no, instance, gen, cmd_id, range |
| `command_receipt` | cmd_id, status(`completed`/`cancelled`) |
| `cache_publish` | device, slot, queue_no, instance, gen, entry_id, range |
| `invalidate_ack` | device, slot, queue_no, instance, gen, range |
| `handoff_request` | request_id, device, from_owner, to_owner, expected_source_version, new_gen, range |

`range` 统一为 `{"start": int, "end": int}`，要求 `0 <= start < end <= 2^52`。

成功输出（节选）：

```json
{
  "ok": true,
  "case_id": "...",
  "accepted": true,
  "head_before": 5,
  "commit_head": 6,
  "replayed_event_ids": [],
  "event_results": [ {"event_id": "...", "effect": "...", "seq": 1} ],
  "handoff_receipts": [ {"receipt_id": "rcpt-...", "request_id": "...",
    "device": "...", "range": {"start": 0, "end": 4096},
    "from_owner": "A", "to_owner": "B", "new_gen": 2,
    "replaced_gens": [1], "source_version": 3, "commit": 6} ],
  "new_receipts": [ ]
}
```

### 3.2 inspect 输入 `QUERY.json`

```json
{ "case_id": "string", "commit": 6, "range": {"start": 0, "end": 4096} }
```

`commit` 可省略（默认当前头）；`range` 可省略（审计全空间）。输出字段见 2.5。

### 3.3 schedule 输入 `CASE.json`

```json
{
  "case_id": "string",
  "windows": [
    {"window_id": "w1", "start": 0, "duration": 40,
     "unresponsive_queues": [{"slot": "s0", "queue_no": 0}]}
  ],
  "targets": [
    {"target_id": "t1", "device": "dev0",
     "range": {"start": 0, "end": 4096}, "deadline": 260,
     "from_owner": "tenant-alpha", "to_owner": "tenant-beta",
     "requirements": [
       {"kind": "invalidate", "slot": "s0", "queue_no": 0,
        "range": {"start": 0, "end": 4096}},
       {"kind": "drain", "slot": "s1", "queue_no": 1}
     ]}
  ],
  "commands": [
    {"command_id": "c1", "kind": "invalidate", "slot": "s0", "queue_no": 0,
     "duration": 6, "range": {"start": 0, "end": 4096},
     "resources": ["bus"],
     "windows": [{"window_id": "w1", "offset": 0}]}
  ]
}
```

语义：

- 一条命令确认一个队列的连续区间（`invalidate`）或排空其在途命令（`drain`）；
  每个候选可有多个可选窗口，但同一 `command_id` 至多执行一次。
- 队列本身是隐式冲突资源；同窗口内时间重叠且共享显式 `resources` 的命令不能同时选。
- 允许的故障是**任一维护窗口内至多一个声明的队列不可响应**。计划必须事先固定
  （主备窗口不能在运行时各自临时选方案），并在基线与每个故障情形下都按时交接。
- 求解器输出鲁棒性证明：对基线和每个 `(窗口, 队列)` 故障，列出被阻断的命令并断言
  所有目标仍按时满足。

目标按字典序依次最小化：

1. 所选命令暂停时长之和 `total_pause_duration`；
2. 命令数 `command_count`；
3. 按 `(执行起点, 窗口 id, offset, 命令 id)` 的有序列表 `ordered_key`。

无解时返回 `feasible: false` 与 `blocker_report`：最早的不可交接区间、未被覆盖的
队列条件，以及原因（`no_command_on_queue` / `no_timely_window` /
`range_uncoverable` / `solver_exhausted_conflicts_or_faults`）。

### 3.4 求解算法与最优性核对

- 生产求解器是**需求驱动的分支限界**：先为每个需求枚举经证明可在全部故障下存活的
  最小鲁棒覆盖集，再按“最受限需求优先”分支，用可加下界与冲突剪枝；
- `Solver.brute_force_plan()` 是独立的子集×摆放穷举器（限 ≤8 条命令），测试中对
  每个小用例核对两个求解器的目标值完全一致；
- 规定规模用例 `cases/schedule_scale_24_64_8.json` 为 24 条候选命令、64 段区间、
  8 个队列，在普通 CPU 上约 0.1 秒完成。

---

## 4. 合成场景一览（`cases/`）

| 文件 | 覆盖的验收要点 |
|---|---|
| `apply_full_lifecycle.json` | 授权→大区间映射→缓存发布→子区间重映射保留两侧→部分确认合并→命令登记/撤销/回执→安全交接全链路 |
| `apply_safety_rejections.json` | 撤销后补登记、证据未清交接、过期源版本等负例 |
| `schedule_short_hole.json` | 局部大区间失效只留下短孔 |
| `schedule_replay_after_handoff.json` | 换挂后旧确认不能算数，失效与排空都需冗余覆盖 |
| `schedule_two_devices_same_page.json` | 同页两个设备的队列残留必须分别清零 |
| `schedule_primary_backup_fixed.json` | 主备窗口不能各自临时选方案，单一固定计划容忍双侧故障 |
| `schedule_bruteforce_crosscheck.json` | 小规模独立穷举核对计划最优性（含慢速诱饵命令） |
| `schedule_scale_24_64_8.json` | 24 命令 / 64 区间 / 8 队列规模与时限 |

---

## 5. 双进程并发验证

`mapping_guard/concurrency.py` 使用独立操作系统进程（非线程）和一个仅监听
localhost 的 TCP 同步屏障服务器，证明四个必需行为。测试通过环境变量
`MAPPING_GUARD_BARRIER_URL` / `MAPPING_GUARD_BARRIER_PHASES` /
`MAPPING_GUARD_ABORT_REQUEST` 注入故障；正常 CLI 运行不设置这些变量，钩子完全
休眠。

1. **首次交接竞争** `scenario_first_handoff_race`：两个进程在屏障处同步后同时开启
   `BEGIN IMMEDIATE`；恰一个提交成功，另一个在自己的事务内重新核对后以
   `version_conflict` 失败，交接表恰一行。
2. **提交前中止** `scenario_pre_commit_abort`：故障注入使写入方在 COMMIT 前回滚，
   五个前置事件保留、交接表零行，随后新进程重试成功。
3. **提交后响应丢失** `scenario_post_commit_loss`：获胜进程在 COMMIT 后被杀；新进程
   携带相同 `request_id` 重试，得到 `idempotent_replay` 与同一份原始回执，仍只有
   一行交接记录。
4. **历史视图合法性** `scenario_historical_view`：读进程在提交 5 拍摄快照（映射已
   撤销、无有效属主、无交接可见），越过屏障后再看提交 6，只能读到当时合法的新属主。

对应断言位于 `tests/test_concurrency.py`。

---

## 6. SQLite 持久化结构

只存区间规模的行，表结构如下（`storage.py` 内 DDL 为权威定义）：

- `meta(key, value)`：schema 版本、case 标识；
- `events(seq PK AUTOINCREMENT, event_id UNIQUE, type, payload)`：只增事件日志，
  `payload` 为规范化 JSON；
- `handoffs(request_id PK, content_hash, commit_seq, receipt)`：幂等表。

不存在任何按页编号展开的表；窗口再大也只产生区间行。

## 7. 目录结构

```
mapping_guard/
  __init__.py        # 常量（地址上界 2^52）
  __main__.py        # CLI 入口（apply/inspect/schedule）
  ranges.py          # 半开区间代数（相交/相减/合并/覆盖判定）
  errors.py          # 字段级结构错误与规则错误、退出码
  validation.py      # 全部输入信封的字段级校验
  model.py           # 状态机、安全规则、审计阻塞计算
  storage.py         # SQLite 事件日志、单事务交接、幂等、历史重放
  scheduler.py       # 鲁棒维护计划分支限界求解 + 穷举参考实现
  concurrency.py     # 双进程屏障与四个并发场景
cases/               # 确定性合成场景与生成器
tests/               # unittest 断言测试（49 个）
```
