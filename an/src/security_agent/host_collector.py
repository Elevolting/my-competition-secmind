"""Read actual host inventory. Findings are exposure observations, not attacks."""
from __future__ import annotations

import base64
import json
import platform
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import psutil


def collect_security_events() -> dict:
    """Read Windows failed-logon events; preserve permission errors as unknown data."""
    if platform.system() != 'Windows':
        return {'records': [], 'errors': ['该采集器需要 Windows Security 事件日志'], 'complete': False}
    script = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
  $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 200 -ErrorAction Stop)
  $rows = @($events | ForEach-Object {
    $xml = [xml]$_.ToXml(); $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) { $fields[[string]$item.Name] = [string]$item.'#text' }
    [pscustomobject]@{record_id=$_.RecordId; time=$_.TimeCreated.ToUniversalTime().ToString('o'); event_id=$_.Id; source_ip=$fields['IpAddress']; logon_type=$fields['LogonType']; status=$fields['Status']}
  })
  @{records=$rows; errors=@(); complete=$true} | ConvertTo-Json -Depth 5 -Compress
} catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @{records=@(); errors=@(); complete=$true} | ConvertTo-Json -Compress }
  else { @{records=@(); errors=@($_.Exception.Message); complete=$false} | ConvertTo-Json -Compress }
}
'''
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
        capture_output=True, encoding='utf-8-sig', errors='replace', timeout=25,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        return {'records': [], 'errors': [result.stderr.strip()], 'complete': False}
    data = json.loads(result.stdout)
    return {**data, 'source': 'Windows Security / 4625', 'window_hours': 24, 'limit': 200,
            'collected_at': datetime.now(UTC).isoformat()}


def collect_host() -> dict:
    errors = []
    processes = []
    for process in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
        try:
            processes.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            errors.append({'source': 'process', 'pid': process.pid, 'error': type(exc).__name__})
    listeners = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                listeners.append({'address': conn.laddr.ip, 'port': conn.laddr.port, 'pid': conn.pid,
                                  'protocol': 'tcp', 'wildcard': conn.laddr.ip in {'0.0.0.0', '::'}})
    except (psutil.AccessDenied, OSError) as exc:
        errors.append({'source': 'listeners', 'error': str(exc)})
    listeners.sort(key=lambda item: (item['port'], item['address']))
    by_pid = {item['pid']: item['name'] for item in processes}
    for item in listeners:
        item['process'] = by_pid.get(item['pid'], 'unknown')
    interfaces = []
    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family in (socket.AF_INET, socket.AF_INET6):
                interfaces.append({'name': name, 'address': address.address, 'netmask': address.netmask})
    findings = [{'rule_id': 'LOCAL-WILDCARD-LISTENER', 'severity': 'info',
                 'message': f"{item['process']} 在所有接口监听 {item['port']}/tcp，需核对访问控制",
                 'evidence': item} for item in listeners if item['wildcard']]
    return {'collected_at': datetime.now(UTC).isoformat(), 'source': 'psutil', 'scope': 'local_host',
            'hostname': socket.gethostname(), 'platform': platform.platform(),
            'boot_time': datetime.fromtimestamp(psutil.boot_time(), UTC).isoformat(),
            'processes': processes, 'listeners': listeners, 'interfaces': interfaces,
            'memory': psutil.virtual_memory()._asdict(),
            'disk': psutil.disk_usage(str(Path.cwd().anchor))._asdict(),
            'findings': findings, 'errors': errors, 'complete': not errors,
            'interpretation': '监听端口是本机暴露面观察，不代表遭受攻击或存在漏洞。防火墙可进一步限制可达性。'}
