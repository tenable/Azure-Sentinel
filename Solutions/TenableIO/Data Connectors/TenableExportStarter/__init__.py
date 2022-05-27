import logging
import time

import azure.functions as func
import azure.durable_functions as df

from datetime import datetime, timedelta, timezone
from ..exports_store import ExportsTableStore
from ..exports_queue import ExportsQueue, ExportsQueueNames
from ..utils import bootstrap_checks
from ..constants import *
from ..tenable_helper import TenableJobStatus


# connection_string = os.environ['AzureWebJobsStorage']
# stats_table_name = ExportsTableNames.TenableExportStatsTable.value
# assets_export_table_name = ExportsTableNames.TenableAssetExportTable.value
# vuln_export_table_name = ExportsTableNames.TenableVulnExportTable.value
# assets_queue_name = ExportsQueueNames.TenableAssetExportsQueue.value
# vuln_queue_name = ExportsQueueNames.TenableVulnExportsQueue.value

# orchestrator_function_name = 'TenableExportsOrchestrator'
# cleanup_orchestrator_function_name = 'TenableCleanUpOrchestrator'

JOB_ACTIVE_STATUSES = [
    TenableJobStatus.pending.value,
    TenableJobStatus.running.value
]

JOB_TERMINAL_STATUSES = [
    TenableJobStatus.completed.value,
    TenableJobStatus.failed.value,
    TenableJobStatus.canceled.value
]


async def start_and_save_new_export_orchestration(
    client: df.DurableOrchestrationClient,
    stats_table: ExportsTableStore,
    last_synced_timestamp: float
) -> str:
    instance_id = await client.start_new(
        ORCHESTRATOR_FUNCTION_NAME, None, { 'startTimestamp': last_synced_timestamp + 1 }
    )

    stats_table.merge('main', 'current', {
        'exportsInstanceId': instance_id,
        'currentJobStartTimestamp': time.time(),
        'currentJobStatus': TenableJobStatus.pending.value,
        'lastSyncedTimestamp': last_synced_timestamp  # indicator that data hasn't yet not synced even once.
    })

    return instance_id


async def start_new_orchestrator(client: df.DurableOrchestrationClient, job_info: dict = None):
    stats_table = ExportsTableStore(STORAGE_ACCOUNT_CONNECTION_STRING, STATS_TABLE_NAME)

    if job_info:
        export_instance_id = job_info['exportsInstanceId']
        current_job_status = job_info.get('currentJobStatus')
        export_frequency = EXPORT_SCHEDULE_MINUTES * 60
        # handling edge case where currentJobStatus and other new fields are not
        # present in table due to old table schema.
        if not current_job_status:
            existing_orchestration = await client.get_status(export_instance_id)
            current_orchestration_status = existing_orchestration.runtime_status
            current_time = time.mktime(datetime.now().timetuple())
            last_synced_timestamp = current_time - (60 * 60 * 24)

            # wait for sometime for current running orchestration to finish,
            # before cancelling it
            if current_orchestration_status not in ORCHESTRATOR_TERMINAL_STATUSES:
                created_time = time.mktime(existing_orchestration.created_time.timetuple())
                time_to_wait = export_frequency - (current_time - created_time)

                if time_to_wait <= 0:
                    try:
                        logging.info('Trying to terminate existing job as max-wait-time has elapsed.')
                        await client.terminate(existing_orchestration.instance_id, f'Waited for maximum allowed time: {export_frequency}')
                    except Exception as exc:
                        logging.error('An error has occurred while terminate orchestration %s', existing_orchestration.instance_id)
                        logging.exception(exc)

                    instance_id = await start_and_save_new_export_orchestration(client, stats_table, last_synced_timestamp)
                else:
                    logging.info(f'Will wait for {time_to_wait} seconds for current orchestration to finish.')
            else:
                instance_id = await start_and_save_new_export_orchestration(client, stats_table, last_synced_timestamp)
        else:
            current_job_status = job_info['currentJobStatus']
            last_synced_timestamp = job_info['lastSyncedTimestamp']
            current_job_start_timestamp = job_info['currentJobStartTimestamp']
            current_job_sub_status = job_info.get('currentJobSubStatus', '')
            current_job_end_timestamp = job_info.get('currentJobEndTimestamp', None)

            existing_orchestration = await client.get_status(export_instance_id)
            current_orchestration_status = existing_orchestration.runtime_status

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
                if current_job_status not in JOB_TERMINAL_STATUSES:
                    logging.warning('Expecting job to be terminated when orchestration finished.')

                time_elapsed_since_job_completion = time.time() - current_job_end_timestamp
                time_to_wait = export_frequency - time_elapsed_since_job_completion

                if time_to_wait <= 0:
                    # instance_id = await client.start_new(
                    #     ORCHESTRATOR_FUNCTION_NAME, None,
                    #     {'startTimestamp': last_synced_timestamp + 1}
                    # )

                    # stats_table.merge('main', 'current', {
                    #     'exportsInstanceId': instance_id,
                    #     'currentJobStartTimestamp': time.time(),
                    #     'currentJobStatus': TenableJobStatus.pending
                    # })
                    instance_id = await start_and_save_new_export_orchestration(client, stats_table, last_synced_timestamp)
                else:
                    logging.info(f'Waiting period on. Will wait for {time_to_wait} seconds before starting new job.')

                    return None
            else:
                if current_job_status not in JOB_ACTIVE_STATUSES:
                    logging.warning('Expecting job to be active when orchestration is running.')

                time_elapsed_since_job_start = time.time() - current_job_start_timestamp
                time_to_wait = export_frequency - time_elapsed_since_job_start

                # if max time has elapsed
                if time_to_wait <= 0:
                    try:
                        logging.info('Updating currentJobStatus to canceled status.')
                        #   update the job status to cancelled along with timestamp dtls
                        stats_table.merge('main', 'current', {
                            'currentJobEndTimestamp': time.time(),
                            'currentJobStatus': TenableJobStatus.canceled.value
                        })

                        logging.warning('Trying to terminate orchestration %s', existing_orchestration.instance_id)
                        #   cancel the job
                        await client.terminate(existing_orchestration.instance_id, f'Waited for maximum allowed time: {export_frequency}')
                    except Exception as exc:
                        logging.error('An error has occurred while terminate orchestration %s', existing_orchestration.instance_id)
                        logging.exception(exc)
                else:
                    # wait for running job to geet finish.
                    logging.info(f'Current job running. Will wait for ${time_to_wait} seconds before starting new job.')

                return None
    else:
        # instance_id = await client.start_new(
        #     ORCHESTRATOR_FUNCTION_NAME, None, { 'startTimestamp': 0 }
        # )

        # stats_table.merge('main', 'current', {
        #     'exportsInstanceId': instance_id,
        #     'currentJobStartTimestamp': time.time(),
        #     'currentJobStatus': TenableJobStatus.pending,
        #     'lastSyncedTimestamp': -1 # indicator that data hasn't yet not synced even once.
        # })

        #'lastSyncedTimestamp': -1 # indicator that data hasn't yet not synced even once.
        instance_id = await start_and_save_new_export_orchestration(client, stats_table, -1)

    # logging.info(f"Started orchestration with ID = '{instance_id}'.")
    # stats_table.merge('main', 'current', {
    #     'exportsInstanceId': instance_id
    # })
    return instance_id


async def start_new_cleanup_orchestrator(client, job_info: dict = None):
    stats_table = ExportsTableStore(STORAGE_ACCOUNT_CONNECTION_STRING, STATS_TABLE_NAME)

    cleanup_instance_id = job_info.get('cleanupInstanceId') if job_info else None
    if cleanup_instance_id:
        existing_cleanup_instance = await client.get_status(cleanup_instance_id)
        existing_status = existing_cleanup_instance.runtime_status

        if existing_status in ORCHESTRATOR_TERMINAL_STATUSES:
            instance_id = await client.start_new(CLEANUP_ORCHESTRATOR_FUNCTION_NAME, None, None)

            stats_table.merge('main', 'current', {
                'cleanupInstanceId': instance_id
            })
        else:
            logging.info(f'Cleanup orchestrator is in {existing_status}')

            return None
    else:
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
        # logging.info('checking if an existing export instance is present in db...')

        # export_instance_id = job_info.get('exportsInstanceId', '')
        # logging.info(f'exports instance id value: {export_instance_id}')

        # if not export_instance_id == '':
        #     logging.info(f'Located an existing exports orchestrator instance: {export_instance_id}')

        #     existing_instance = await client.get_status(export_instance_id)

        #     logging.info(f'Existing instance details: {existing_instance}, status: {existing_instance.runtime_status}')

        #     if existing_instance is None or existing_instance.runtime_status in ORCHESTRATOR_TERMINAL_STATUSES:
        #         # check if time to wait has elapsed
        #         # if yes then
        #         #   trigger new run
        #         new_instance_id = await start_new_orchestrator(client, job_info, existing_instance)
        #         logging.info(f'started new instance -- {new_instance_id}')
        #     else:
        #         logging.info(
        #             'Export job is already currently running. Will try again later.')
        #         # check if max allowed time to run job has reached
        #         # if yes
        #         #   cancel the job
        #         #   start new job
        #         # else
        #         #   wait for the job get finished
        # else:
        #     logging.info('not a first run, but no instance id found yet.')
        #     logging.info('starting new instance id.')
        #     new_instance_id = await start_new_orchestrator(client)
        #     logging.info(f'started new instance -- {new_instance_id}')
        instance_id = await start_new_orchestrator(client, job_info)
        if instance_id:
            logging.info(f'started new exports orchestrator instance -- {instance_id}')

        # logging.info('checking for an existing cleanup instance was found...')
        # cleanup_singleton_instance_id = job_info['cleanupInstanceId'] if 'cleanupInstanceId' in job_info else ''
        # if not cleanup_singleton_instance_id == '':
        #     logging.info(
        #         f'Located an existing cleanup orchestrator instance: {cleanup_singleton_instance_id}')
        #     existing_cleanup_instance = await client.get_status(cleanup_singleton_instance_id)
        #     logging.info(existing_cleanup_instance)
        #     logging.info(existing_cleanup_instance.runtime_status)
        #     if existing_cleanup_instance is None or existing_cleanup_instance.runtime_status in [
        #         df.OrchestrationRuntimeStatus.Completed, df.OrchestrationRuntimeStatus.Failed,
        #         df.OrchestrationRuntimeStatus.Terminated, None]:
        #         new_cleanup_instance_id = await start_new_cleanup_orchestrator(client)
        #         logging.info(
        #             f'started new instance -- {new_cleanup_instance_id}')
        #     else:
        #         logging.info(
        #             'Cleanup job is already currently running. Will try again later.')
        # else:
        #     logging.info(
        #         'not a first run, but no cleanup instance id found yet.')
        #     logging.info('starting new cleanup instance id.')
        #     cleanup_new_instance_id = await start_new_cleanup_orchestrator(client)
        #     logging.info(f'started new instance -- {cleanup_new_instance_id}')
        cleanup_new_instance_id = await start_new_cleanup_orchestrator(client, job_info)
        if instance_id:
            logging.info(f'started new cleanup orchestrator instance -- {cleanup_new_instance_id}')
    else:
        first_run_setup()
        await start_new_orchestrator(client)
        await start_new_cleanup_orchestrator(client)
        return
