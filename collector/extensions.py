"""Instances d'extensions Flask partagées entre les blueprints.

Séparé de app.py pour éviter les imports circulaires : les blueprints
(collector/api.py, collector/auth.py, ...) ont besoin de @limiter.limit(...)
au moment de la définition de leurs routes (import time), ce qui arrive
avant que create_app() n'ait fini de construire l'application. L'instance
`limiter` ci-dessous existe dès le premier import du module — elle est
ensuite liée à l'app Flask via limiter.init_app(app) dans create_app(),
qui lit app.config["RATELIMIT_DEFAULT"] / ["RATELIMIT_STORAGE_URI"].
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
