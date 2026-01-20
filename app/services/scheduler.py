from apscheduler.schedulers.background import BackgroundScheduler

from app.services.config import settings
from app.services.backup import run_scheduled_checks


scheduler = BackgroundScheduler()


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(run_scheduled_checks, "interval", seconds=settings.scheduler_interval_seconds)
    scheduler.start()
