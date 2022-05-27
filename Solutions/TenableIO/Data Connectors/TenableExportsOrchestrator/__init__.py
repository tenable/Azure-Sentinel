import logging
import os
from datetime import timedelta, datetime, timezone
from time import time

import azure.functions as func
import azure.durable_functions as df

from ..exports_store import ExportsTableStore, TenableStatus
from ..tenable_helper import TenableExportType, TenableJobSubStatus, TenableJobStatus
from ..constants import *

#connection_string = os.environ['AzureWebJobsStorage']
#stats_table_name = ExportsTableNames.TenableExportStatsTable.value
#export_schedule_minutes = int(
#    os.getenv('TenableExportScheduleInMinutes', '1440'))
#start_asset_job_name = 'TenableStartAssetExportJob'
#start_vuln_job_name = 'TenableStartVulnExportJob'
#asset_orchestrator_name = 'TenableAssetExportOrchestrator'
#vuln_orchestrator_name = 'TenableVulnExportOrchestrator'


def orchestrator_function(context: df.DurableOrchestrationContext):
    logging.info('started main orchestrator')
    logging.info(
        f'instance id: f{context.instance_id} at {context.current_utc_datetime}')

    input_dict = context.get_input()
    filter_by_time = int(input_dict['startTimestamp'])

    logging.info('filter by time: %d', filter_by_time)

    try:
        stats_store = ExportsTableStore(STORAGE_ACCOUNT_CONNECTION_STRING, STATS_TABLE_NAME)

        last_synced_timestamp = time()
        asset_export_job_id = yield context.call_activity(START_ASSET_FUNCTION_NAME, filter_by_time)
        logging.info('retrieved a new asset job ID')
        logging.warning(
            f'instance id: f{context.instance_id} working with asset export job {asset_export_job_id}, sending to sub orchestrator')

        stats_store.merge('main', 'current', {'currentJobStatus': TenableJobSubStatus.asset_export_started.value})
        stats_store.merge(asset_export_job_id, 'prime', {
            'status': TenableStatus.processing.value,
            'exportType': TenableExportType.asset.value,
            'failedChunks': '',
            'chunks': '',
            'totalChunksCount': 0,
            'jobTimestamp': filter_by_time,
            'startedAt': context.current_utc_datetime.timestamp()
        })

        logging.info(
            f'saved {asset_export_job_id} to stats table. moving to start vuln job.')

        vuln_export_job_id = yield context.call_activity(START_VULN_FUNCTION_NAME, filter_by_time)

        logging.info('retrieved a new vuln job ID')
        logging.warn(
            f'instance id: f{context.instance_id} working with vuln export job {vuln_export_job_id}, sending to sub orchestrator')

        stats_store.merge('main', 'current', { 'currentJobSubStatus': TenableJobSubStatus.vuln_export_started })
        stats_store.merge(vuln_export_job_id, 'prime', {
            'status': TenableStatus.processing.value,
            'exportType': TenableExportType.vuln.value,
            'failedChunks': '',
            'chunks': '',
            'totalChunksCount': 0,
            'jobTimestamp': filter_by_time,
            'startedAt': context.current_utc_datetime.timestamp()
        })

        asset_export = context.call_sub_orchestrator(ASSET_ORCHESTRATOR_FUNCTION_NAME, {
            'timestamp': filter_by_time,
            'assetJobId': asset_export_job_id,
            'mainOrchestratorInstanceId': context.instance_id
        })
        stats_store.merge(asset_export_job_id, 'prime', {
            'status': TenableStatus.sent_to_sub_orchestrator.value
        })

        vuln_export = context.call_sub_orchestrator(VULN_ORCHESTRATOR_FUNCTION_NAME, {
            'timestamp': filter_by_time,
            'vulnJobId': vuln_export_job_id,
            'mainOrchestratorInstanceId': context.instance_id
        })
        stats_store.merge(vuln_export_job_id, 'prime', {
            'status': TenableStatus.sent_to_sub_orchestrator.value
        })

        results = yield context.task_all([asset_export, vuln_export])
        logging.info('Finished both jobs!')
        logging.info(results)

        try:
            asset_job_finished = results[0]
            asset_id = asset_job_finished['id'] if 'id' in asset_job_finished else ''
            chunks = asset_job_finished['chunks'] if 'chunks' in asset_job_finished else [
            ]
            chunk_ids = ','.join(str(c) for c in chunks)
            if asset_id != '':
                stats_store.merge(asset_id, 'prime', {
                    'status': TenableStatus.finished.value,
                    'chunks': chunk_ids,
                    'totalChunksCount': len(chunks)
                })

            stats_store.merge('main', 'current', { 'currentJobSubStatus': TenableJobSubStatus.asset_export_finished })
        except IndexError as e:
            logging.warn('asset job returned no results')
            stats_store.merge('main', 'current', { 'currentJobSubStatus': TenableJobSubStatus.asset_export_failed })
            raise e

        try:
            vuln_job_finished = results[1]
            vuln_id = vuln_job_finished['id'] if 'id' in vuln_job_finished else ''
            chunks = vuln_job_finished['chunks'] if 'chunks' in vuln_job_finished else [
            ]
            chunk_ids = ','.join(str(c) for c in chunks)
            if vuln_id != '':
                stats_store.merge(vuln_id, 'prime', {
                    'status': TenableStatus.finished.value,
                    'chunks': chunk_ids,
                    'totalChunksCount': len(chunks)
                })
            stats_store.merge('main', 'current', { 'currentJobSubStatus': TenableJobSubStatus.vuln_export_finished })

        except IndexError as e:
            logging.warn('vuln job returned no results')
            stats_store.merge('main', 'current', { 'currentJobSubStatus': TenableJobSubStatus.vuln_export_failed })
            raise e
    except Exception as exc:
        logging.exception(exc)
        stats_store.merge(
            'main', 'current',
            {
                'currentJobStatus': TenableJobStatus.failed.value,
                'currentJobEndTimestamp': time()
            }
        )
    else:
        stats_store.merge(
            'main', 'current',
            {
                'currentJobStatus': TenableJobStatus.completed.value,
                'currentJobEndTimestamp': time(),
                'lastSyncedTimestamp': last_synced_timestamp
            }
        )

    # next_check = context.current_utc_datetime + \
    #     timedelta(minutes=EXPORT_SCHEDULE_MINUTES)
    # yield context.create_timer(next_check)
    # context.continue_as_new(None)


main = df.Orchestrator.create(orchestrator_function)
