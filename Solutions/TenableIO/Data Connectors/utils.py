from constants import EXPORT_SCHEDULE_MINUTES


def bootstrap_checks():
    if EXPORT_SCHEDULE_MINUTES <= 10:
        raise Exception(f'TenableExportScheduleInMinutes can not be less than an hour.')

    if EXPORT_SCHEDULE_MINUTES >= 1440:
        raise Exception(f'TenableExportScheduleInMinutes can not be less than 24 hours.')

    # Add other checks in the future.
