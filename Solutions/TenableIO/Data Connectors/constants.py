import os
import azure.durable_functions as df

from exports_store import ExportsTableNames
from exports_queue import ExportsQueueNames
from tenable_helper import TenableJobStatus


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

# other constants
ORCHESTRATOR_TERMINAL_STATUSES = [
    df.OrchestrationRuntimeStatus.Completed,
    df.OrchestrationRuntimeStatus.Failed,
    df.OrchestrationRuntimeStatus.Canceled,
    df.OrchestrationRuntimeStatus.Terminated,
    None
]

JOB_ACTIVE_STATUSES = [
    TenableJobStatus.pending,
    TenableJobStatus.running
]

JOB_TERMINAL_STATUSES = [
    TenableJobStatus.completed,
    TenableJobStatus.failed,
    TenableJobStatus.canceled
]
