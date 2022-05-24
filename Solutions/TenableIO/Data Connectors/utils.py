from constants import EXPORT_SCHEDULE_MINUTES


def bootstrap_checks():
    if EXPORT_SCHEDULE_MINUTES <= 60:
        raise Exception(f'TenableExportScheduleInMinutes can not be less than an hour.')

    # Add other checks in the future.
