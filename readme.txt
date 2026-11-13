筛查业务指标审计服务。现有口径合同、批次导入、分母重建、期间核对和抽样追踪形成审计底稿。

环境：Linux，Python 3.11.2 或更新的兼容版本。所有依赖来自 Python 标准库，无需安装第三方包。

测试：python3 -m unittest discover -s tests/kpi_audit -p 'test_*.py'
构建：python3 -m compileall -q screening_kpi_auditor
验收：python3 -m screening_kpi_auditor.main fixtures/demo.json --db /tmp/screening_kpi_auditor-acceptance.sqlite3

目录：screening_kpi_auditor 保存业务处理与存储模块；tests/kpi_audit 保存业务回归；fixtures/demo.json 为原有业务样例，fixtures/analysis 为经营分析资料及字段说明。

原有验收命令每次使用新的 SQLite 路径，避免复用上次状态。新增输入完整性检查：
python3 -m unittest discover -s tests/analysis_inputs -v

容器运行可使用已经预装的 ccusr/prepared:3f007a95fcee-4441968e5ff6 镜像；将当前仓库只读挂载至 /source，在容器内复制到 /tmp/product 后运行上述命令。依赖准备和正式运行分离，运行过程中不需要网络访问。
