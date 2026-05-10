import json
from asgiref.sync import sync_to_async
from api.models import ScanRun, RunReport
from api.reporting import build_report, serialize_report_json, serialize_report_md

def register(mcp):

    @mcp.tool()
    async def generate_report(run_id: str, format: str = "json") -> str:
        """스캔 결과 보고서를 생성한다.
        format: json 또는 md
        """
        def _build():
            report = build_report(run_id)
            scan_run = ScanRun.objects.get(run_id=run_id)
            rr, _ = RunReport.objects.update_or_create(
                scan_run=scan_run,
                defaults={
                    "json": serialize_report_json(report),
                    "markdown": serialize_report_md(report),
                },
            )
            return report, rr

        report, rr = await sync_to_async(_build)()

        if format == "md":
            return json.dumps({
                "run_id": run_id,
                "report_id": str(rr.report_id),
                "format": "md",
                "content": report.md_text,
            })
        return json.dumps({
            "run_id": run_id,
            "report_id": str(rr.report_id),
            "format": "json",
            "content": report.json_obj,
        })

