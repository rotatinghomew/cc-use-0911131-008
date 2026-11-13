筛查业务指标审计服务。现有口径合同、批次导入、分母重建、期间核对和抽样追踪形成审计底稿。

环境：Linux，Python 3.11.2 或更新的兼容版本。所有依赖来自 Python 标准库，无需安装第三方包。

测试：python3 -m unittest discover -s tests/kpi_audit -p 'test_*.py'
构建：python3 -m compileall -q screening_kpi_auditor
验收：python3 -m screening_kpi_auditor.main fixtures/demo.json --db /tmp/screening_kpi_auditor-acceptance.sqlite3

目录：screening_kpi_auditor 保存业务处理与存储模块；tests/kpi_audit 保存业务回归；fixtures/demo.json 为原有业务样例，fixtures/analysis 为经营分析资料及字段说明。

原有验收命令每次使用新的 SQLite 路径，避免复用上次状态。新增输入完整性检查：
python3 -m unittest discover -s tests/analysis_inputs -v

安全发布规划（safe_release）在同一套指标口径与审计底稿上做多维聚合与可发布性
推理，不是权限管理或报表页面：
  入口：python3 -m screening_kpi_auditor.safe_release \
          --input fixtures/analysis/input.json \
          --database <审计台账.sqlite3> --output <对外发布.json>
  说明：按 indicator 的去重键、生效日重建分子/分母，迟到补录（known_at 晚于
  as_of）、口径外记录、未知维度与零分母均逐条留痕；多个透视共享同一批原子层
  与同一套 cell_id，抑制决策全局一致。可发布性由精确有理数单纯形 LP 审计：在
  已发布单元的全部线性加减关系、盒子边界与历史已发布固定行下，对每个低于最低
  单元人数的敏感单元求分子/分母整数可行区间，区间宽度不足即判不安全；约束矩阵
  全幺模，LP 边界即整数可行域边界。互补抑制以区间宽度引导贪心，最终方案必须再
  过一次完整 LP 审计，无法证明安全则整单拒绝。证书只对请求内线性关系与登记的
  历史发布负责，不声称覆盖任意外部知识。内部底稿（真值、披露区间、记录处置）只
  写数据库且只增不改，外部文件只含白名单字段，隐藏值一律 null。
  测试：python3 -m unittest discover -s tests/safe_release -v

容器运行可使用已经预装的 ccusr/prepared:3f007a95fcee-4441968e5ff6 镜像；将当前仓库只读挂载至 /source，在容器内复制到 /tmp/product 后运行上述命令。依赖准备和正式运行分离，运行过程中不需要网络访问。
