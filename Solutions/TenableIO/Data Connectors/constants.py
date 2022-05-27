import os
import azure.durable_functions as df

from exports_store import ExportsTableNames
from exports_queue import ExportsQueueNames


# env variables
STORAGE_ACCOUNT_CONNECTION_STRING = os.environ['AzureWebJobsStorage']
EXPORT_SCHEDULE_MINUTES = int(os.getenv('TenableExportScheduleInMinutes', '1440'))

# table names
STATS_TABLE_NAME = ExportsTableNames.TenableExportStatsTable.value
ASSETS_EXPORT_TABLE_NAME = ExportsTableNames.TenableAssetExportTable.value
VULN_EXPORT_TABLE_NAME = ExportsTableNames.TenableVulnExportTable.value
ASSETS_QUEUE_NAME = ExportsQueueNames.TenableAssetExportsQueue.value
VULN_QUEUE_NAME = ExportsQueueNames.TenableVulnExportsQueue.value

# function names
ORCHESTRATOR_FUNCTION_NAME = 'TenableExportsOrchestrator'
CLEANUP_ORCHESTRATOR_FUNCTION_NAME = 'TenableCleanUpOrchestrator'
START_ASSET_FUNCTION_NAME = 'TenableStartAssetExportJob'
START_VULN_FUNCTION_NAME = 'TenableStartVulnExportJob'
ASSET_ORCHESTRATOR_FUNCTION_NAME = 'TenableAssetExportOrchestrator'
VULN_ORCHESTRATOR_FUNCTION_NAME = 'TenableVulnExportOrchestrator'

# other constants
ORCHESTRATOR_TERMINAL_STATUSES = [
    df.OrchestrationRuntimeStatus.Completed,
    df.OrchestrationRuntimeStatus.Failed,
    df.OrchestrationRuntimeStatus.Canceled,
    df.OrchestrationRuntimeStatus.Terminated,
    None
]
