# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import re
import time

from django.conf import settings
from django.contrib import auth
from django import http as django_http
from django import shortcuts
from django.views.decorators.cache import never_cache  # noqa
from django.views.decorators.csrf import csrf_exempt  # noqa
from django.views.decorators.csrf import csrf_protect  # noqa
from django.views.decorators.debug import sensitive_post_parameters  # noqa

# This is historic and is added back in to not break older versions of
# Horizon, fix to Horizon to remove this requirement was committed in
# Juno
from openstack_auth import user as auth_user

LOG = logging.getLogger(__name__)


@sensitive_post_parameters()
@csrf_exempt
@never_cache
def websso_login(request):
    """Logs a user in using a token from Keystone's POST."""
    referer = request.META.get('HTTP_REFERER', settings.OPENSTACK_KEYSTONE_URL)
    auth_url = re.sub(r'/auth.*', '', referer)

    token = request.POST.get('token')
    if not token: 
        LOG.info('WebSSO user authentication failed. No token was posted to '
                 'the websso login form for authentication.')
        return django_http.HttpResponse('Unauthorized', status=401)

    user = auth.authenticate(request=request, 
                             auth_url=auth_url,
                             token=token) 

    if not (user and user.is_authenticated()):
        LOG.info('WebSSO user authentication failed. No user was able to be '
                 'authenticated from the WebSSO token.')
        return django_http.HttpResponse('Unauthorized', status=401)

    auth.login(request, user)
    res = shortcuts.redirect(settings.LOGIN_REDIRECT_URL)
    auth_user.set_session_from_user(request, user)
    request.session['last_activity'] = int(time.time())
 
    if request.session.test_cookie_worked():
        request.session.delete_test_cookie()

    return res
