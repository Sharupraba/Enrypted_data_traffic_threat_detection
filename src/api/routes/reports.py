import io
import csv
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse
from src.api.database import get_flows, get_alerts
from src.reports.siem_exporter import generate_cef_export, generate_syslog_export

router = APIRouter()

@router.get("/reports/cef")
async def export_cef():
    """
    Export all recorded flows into ArcSight Common Event Format (CEF) standard.
    """
    flows = await get_flows(limit=5000)
    cef_content = generate_cef_export(flows)
    stream = io.StringIO(cef_content)
    return StreamingResponse(
        iter([stream.getvalue()]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=zenith_alerts.cef"}
    )

@router.get("/reports/syslog")
async def export_syslog():
    """
    Export all recorded flows into RFC 5424 Syslog standard log format.
    """
    flows = await get_flows(limit=5000)
    syslog_content = generate_syslog_export(flows)
    stream = io.StringIO(syslog_content)
    return StreamingResponse(
        iter([stream.getvalue()]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=zenith_syslog.log"}
    )

@router.get("/reports/json")
async def export_json():
    """
    Export all flows as a JSON file.
    """
    flows = await get_flows(limit=5000)
    
    # Format and indent JSON
    content = json.dumps(flows, indent=2)
    
    # Return as streamable attachment
    stream = io.StringIO(content)
    return StreamingResponse(
        iter([stream.getvalue()]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=zenith_flow_report.json"}
    )

@router.get("/reports/csv")
async def export_csv():
    """
    Export all flows as a CSV file.
    """
    flows = await get_flows(limit=5000)
    if not flows:
        # Return empty CSV with header
        headers = ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "risk_score", "severity"]
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv")

    # Construct columns from keys
    headers = list(flows[0].keys())
    if "raw_json" in headers:
        headers.remove("raw_json")
        
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    
    for f in flows:
        row = [f.get(h) for h in headers]
        writer.writerow(row)
        
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=zenith_flow_report.csv"}
    )

@router.get("/reports/html", response_class=HTMLResponse)
async def export_html():
    """
    Generates a beautifully styled printer-friendly HTML executive report.
    """
    flows = await get_flows(limit=1000)
    alerts = await get_alerts(limit=1000)
    
    # Calculate some basics
    total_flows = len(flows)
    total_alerts = len(alerts)
    critical_alerts = sum(1 for a in alerts if a.get("severity") == "Critical")
    
    # Simple CSS design
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Intelligence Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #333; margin: 30px; line-height: 1.6; }}
            .header {{ border-bottom: 2px solid #2A3F54; padding-bottom: 10px; margin-bottom: 20px; }}
            .title {{ font-size: 24px; font-weight: bold; color: #2A3F54; }}
            .meta {{ font-size: 12px; color: #777; margin-top: 5px; }}
            .summary-cards {{ display: flex; gap: 20px; margin-bottom: 30px; }}
            .card {{ flex: 1; border: 1px solid #ddd; padding: 15px; border-radius: 6px; background-color: #f9f9f9; }}
            .card-title {{ font-size: 11px; text-transform: uppercase; color: #777; font-weight: bold; }}
            .card-value {{ font-size: 20px; font-weight: bold; margin-top: 5px; color: #1ABB9C; }}
            .card-value.danger {{ color: #E74C3C; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #2A3F54; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
            .badge.critical {{ background-color: #E74C3C; color: white; }}
            .badge.high {{ background-color: #E67E22; color: white; }}
            .badge.medium {{ background-color: #F1C40F; color: black; }}
            .badge.low {{ background-color: #3498DB; color: white; }}
            .badge.safe {{ background-color: #2ECC71; color: white; }}
            @media print {{
                body {{ margin: 0; }}
                button {{ display: none; }}
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <span class="title">Threat Detection & Analysis Report</span>
            <div class="meta">Generated automatically by Threat Detection Engine</div>
            <button onclick="window.print()" style="margin-top: 10px; padding: 8px 12px; font-weight: bold; background: #2A3F54; color: white; border: none; border-radius: 4px; cursor: pointer;">Print to PDF</button>
        </div>

        <div class="summary-cards">
            <div class="card">
                <div class="card-title">Total Monitored Flows</div>
                <div class="card-value">{total_flows}</div>
            </div>
            <div class="card">
                <div class="card-title">Threat Alerts Identified</div>
                <div class="card-value danger">{total_alerts}</div>
            </div>
            <div class="card">
                <div class="card-title">Critical Severity Threat Alerts</div>
                <div class="card-value danger">{critical_alerts}</div>
            </div>
        </div>

        <h3>Active Threat Logs</h3>
        <table>
            <thead>
                <tr>
                    <th>Flow ID</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                    <th>TLS Target (SNI)</th>
                </tr>
            </thead>
            <tbody>
    """
    
    if not alerts:
        html_content += "<tr><td colspan='7' style='text-align:center;'>No threat alerts recorded.</td></tr>"
    else:
        for a in alerts:
            sev_str = str(a.get('severity') or 'Safe')
            sev = sev_str.lower()
            fid = str(a.get('flow_id') or 'UNKNOWN')[:8]
            html_content += f"""
                <tr>
                    <td><code>{fid}...</code></td>
                    <td>{a.get('src_ip') or '0.0.0.0'}:{a.get('src_port') or 0}</td>
                    <td>{a.get('dst_ip') or '0.0.0.0'}:{a.get('dst_port') or 0}</td>
                    <td>{a.get('protocol') or 'TCP'}</td>
                    <td>{a.get('risk_score') or 0}</td>
                    <td><span class="badge {sev}">{sev_str}</span></td>
                    <td><code>{a.get('sni') or 'N/A'}</code></td>
                </tr>
            """
            
    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """
    return html_content
