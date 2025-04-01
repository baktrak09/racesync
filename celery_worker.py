from app import app, make_celery

celery = make_celery(app)

# This is needed so celery -A celery_worker works
app.app_context().push()
