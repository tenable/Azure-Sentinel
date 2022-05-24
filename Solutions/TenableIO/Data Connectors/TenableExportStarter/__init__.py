import logging
import time

import azure.functions as func
import azure.durable_functions as df

from datetime import datetime, timedelta, timezone
from ..exports_store import ExportsTableStore, ExportsTableNames
from ..exports_queue import ExportsQueue, ExportsQueueNames
from ..utils import bootstrap_checks
from ..constants import *


# connection_string = os.environ['AzureWebJobsStorage']
# stats_table_name = ExportsTableNames.TenableExportStatsTable.value
# assets_export_table_name = ExportsTableNames.TenableAssetExportTable.value
# vuln_export_table_name = ExportsTableNames.TenableVulnExportTable.value
# assets_queue_name = ExportsQueueNames.TenableAssetExportsQueue.value
# vuln_queue_name = ExportsQueueNames.TenableVulnExportsQueue.value

# orchestrator_function_name = 'TenableExportsOrchestrator'
# cleanup_orchestrator_function_name = 'TenableCleanUpOrchestrator'


async def start_new_orchestrator(
        client: df.DurableOrchestrationClient,
        existing_instance_dtls: dict = None,
        existing_orchestration: df.DurableOrchestrationStatus = None
):
    stats_table = ExportsTableStore(STORAGE_ACCOUNT_CONNECTION_STRING, STATS_TABLE_NAME)

    if (
        any([all([existing_instance_dtls, existing_orchestration]),
             all([not existing_instance_dtls, not existing_orchestration])])
    ):
        raise Exception('Either both instance and orchestration details should be passed or none.')

    if existing_instance_dtls:
        last_synced_timestamp = existing_instance_dtls['lastSyncedTimestamp']
        current_job_start_timestamp = existing_instance_dtls['currentJobStartTimestamp']
        current_job_end_timestamp = existing_instance_dtls['currentJobEndTimestamp']
        current_job_status = existing_instance_dtls['currentJobStatus']
        current_job_sub_status = existing_instance_dtls['currentJobSubStatus']
        current_orchestration_status = existing_orchestration.runtime_status
        export_frequency = EXPORT_SCHEDULE_MINUTES * 60

        logging.info('*********** Current Job details *************')
        logging.info(f'lastSyncedTimestamp: {last_synced_timestamp}')
        logging.info(f'currentJobStartTimestamp: {current_job_start_timestamp}')
        logging.info(f'currentJobEndTimestamp: {current_job_end_timestamp}')
        logging.info(f'currentJobStatus: {current_job_status}')
        logging.info(f'currentJobSubStatus: {current_job_sub_status}')
        logging.info(f'orchestrationStatus: {current_orchestration_status}')
        logging.info(f'exportFrequency: {export_frequency}')

        if current_orchestration_status in ORCHESTRATOR_TERMINAL_STATUSES:
            # expecting that job status in TERMINAL STATUS
            assert current_job_status in JOB_TERMINAL_STATUSES, 'Expecting job to be terminated when orchestration finished.'
            time_elapsed_since_job_completion = time.time() - current_job_end_timestamp
            time_to_wait = export_frequency - time_elapsed_since_job_completion

            if time_to_wait <= 0:
                instance_id = await client.start_new(
                    ORCHESTRATOR_FUNCTION_NAME, None,
                    {'startTimestamp': last_synced_timestamp + 1}
                )
            else:
                logging.info(f'Waiting period on. Will wait for ${time_to_wait} seconds before starting new job.')
        else:
            assert current_job_status in JOB_ACTIVE_STATUSES, 'Expecting job to be active when orchestration is running.'

            time_elapsed_since_job_start = time.time() - current_job_start_timestamp
            time_to_wait = export_frequency - time_elapsed_since_job_start

            # if max time has elapsed
            if time_to_wait <= 0:
                # TODO: Handle errors while terminate orchestration instance.
                #   cancel the job
                await client.terminate(existing_orchestration.instance_id, f'Waited for maximum allowed time: {export_frequency}')

                #   update the job status to cancelled along with timestamp dtls
                stats_table.merge('main', 'current', {
                    'currentJobEndTimestamp': time.time()
                    'currentJobStatus': TenableJobStatus.canceled
                })
            else:
                # wait for running job to geet finish.
                logging.info(f'Current job running. Will wait for ${time_to_wait} seconds before starting new job.')

        # if job is running
        #   if max time has elapesed
        #       cancel the job
        #       update the job status to cancelled along with timestamp dtls
        # elif job has been terminated
    else:
        instance_id = await client.start_new(ORCHESTRATOR_FUNCTION_NAME, None, {'startTimestamp': start_timestamp})

    logging.info(f"Started orchestration with ID = '{instance_id}'.")
    stats_table.merge('main', 'current', {
        'exportsInstanceId': instance_id
    })
    return instance_id


async def start_new_cleanup_orchestrator(client):
    stats_table = ExportsTableStore(STORAGE_ACCOUNT_CONNECTION_STRING, STATS_TABLE_NAME)
    instance_id = await client.start_new(CLEANUP_ORCHESTRATOR_FUNCTION_NAME, None, None)
    logging.info(f"Started clean up orchestration with ID = '{instance_id}'.")
    stats_table.merge('main', 'current', {
        'cleanupInstanceId': instance_id
    })
    return instance_id


def first_run_setup():
    logging.info('First run detected...')
    logging.info('Setting up the following resources:')
    logging.info(STATS_TABLE_NAME)
    logging.info(ASSETS_EXPORT_TABLE_NAME)
    logging.info(VULN_EXPORT_TABLE_NAME)
    logging.info(ASSETS_QUEUE_NAME)
    logging.info(VULN_QUEUE_NAME)
    stats_table = ExportsTableStore(STORAGE_ACCOUNT_CONNECTION_STRING, STATS_TABLE_NAME)
    stats_table.create()

    asesets_table = ExportsTableStore(
        STORAGE_ACCOUNT_CONNECTION_STRING, ASSETS_EXPORT_TABLE_NAME)
    asesets_table.create()

    vuln_table = ExportsTableStore(STORAGE_ACCOUNT_CONNECTION_STRING, VULN_EXPORT_TABLE_NAME)
    vuln_table.create()

    assets_queue = ExportsQueue(STORAGE_ACCOUNT_CONNECTION_STRING, ASSETS_QUEUE_NAME)
    assets_queue.create()

    vuln_queue = ExportsQueue(STORAGE_ACCOUNT_CONNECTION_STRING, VULN_QUEUE_NAME)
    vuln_queue.create()

    stats_table.post('main', 'current', {
        'exportsInstanceId': '',
        'cleanupInstanceId': '',
        'isFirstRun': False
    })
    return


async def main(mytimer: func.TimerRequest, starter: str) -> None:
    utc_timestamp = datetime.utcnow().replace(
        tzinfo=timezone.utc).isoformat()
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    bootstrap_checks()

    client = df.DurableOrchestrationClient(starter)

    store = ExportsTableStore(
        connection_string=STORAGE_ACCOUNT_CONNECTION_STRING, table_name=STATS_TABLE_NAME)
    logging.info('looking in table storage for running instance')
    job_info = store.get('main', 'current')
    logging.info('results from table storage:')
    logging.info(job_info)

    if job_info is not None:
        logging.info('checking if an existing export instance is present in db...')

        export_instance_id = job_info.get('exportsInstanceId', '')
        logging.info(f'exports instance id value: {export_instance_id}')

        if not export_instance_id == '':
            logging.info(f'Located an existing exports orchestrator instance: {export_instance_id}')

            existing_instance = await client.get_status(export_instance_id)

            logging.info(f'Existing instance details: {existing_instance}, status: {existing_instance.runtime_status}')

            if existing_instance is None or existing_instance.runtime_status in ORCHESTRATOR_TERMINAL_STATUSES:
                # check if time to wait has elapsed
                # if yes then
                #   trigger new run
                new_instance_id = await start_new_orchestrator(client)
                logging.info(f'started new instance -- {new_instance_id}')
            else:
                logging.info(
                    'Export job is already currently running. Will try again later.')
                # check if max allowed time to run job has reached
                # if yes
                #   cancel the job
                #   start new job
                # else
                #   wait for the job get finished
        else:
            logging.info('not a first run, but no instance id found yet.')
            logging.info('starting new instance id.')
            new_instance_id = await start_new_orchestrator(client)
            logging.info(f'started new instance -- {new_instance_id}')

        logging.info('checking for an existing cleanup instance was found...')
        cleanup_singleton_instance_id = job_info['cleanupInstanceId'] if 'cleanupInstanceId' in job_info else ''
        if not cleanup_singleton_instance_id == '':
            logging.info(
                f'Located an existing cleanup orchestrator instance: {cleanup_singleton_instance_id}')
            existing_cleanup_instance = await client.get_status(cleanup_singleton_instance_id)
            logging.info(existing_cleanup_instance)
            logging.info(existing_cleanup_instance.runtime_status)
            if existing_cleanup_instance is None or existing_cleanup_instance.runtime_status in [
                df.OrchestrationRuntimeStatus.Completed, df.OrchestrationRuntimeStatus.Failed,
                df.OrchestrationRuntimeStatus.Terminated, None]:
                new_cleanup_instance_id = await start_new_cleanup_orchestrator(client)
                logging.info(
                    f'started new instance -- {new_cleanup_instance_id}')
            else:
                logging.info(
                    'Cleanup job is already currently running. Will try again later.')
        else:
            logging.info(
                'not a first run, but no cleanup instance id found yet.')
            logging.info('starting new cleanup instance id.')
            cleanup_new_instance_id = await start_new_cleanup_orchestrator(client)
            logging.info(f'started new instance -- {cleanup_new_instance_id}')
    else:
        first_run_setup()
        await start_new_orchestrator(client, True)
        await start_new_cleanup_orchestrator(client)
        return
