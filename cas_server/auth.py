# -*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015-2016 Valentin Samir
"""Some authentication classes for the CAS"""
import sys
import logging
import time
import radius
from ldap3 import Server, Connection
from django.conf import settings
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import connections, DatabaseError
from ifxuser.models import IfxUser

logger = logging.getLogger(__name__)


class RcAuthUser(object):
    '''
    CAS server backend that uses AD, RADIUS and IfxUser
    '''
    def __init__(self, username):
        '''
        Set username and check settings
        '''
        for attr in ['RADIUS_SECRET', 'RADIUS_SERVER', 'AD_SERVER', 'AD_PORT']:
            if not hasattr(settings, attr) or not getattr(settings, attr):
                logger.exception('%s must be defined in settings.py' % attr)
                raise Exception('%s must be defined in settings.py' % attr)
        self.username = username
        self.attributes = None

    def test_password(self, password, code):
        '''
        Tests password against AD and code against RADIUS
        '''
        logger.debug('Testing password for %s', self.username)
        if self.check_ad(password) and self.check_radius(code):
            logger.debug('Password valid')
            try:
                ifxuser = IfxUser.objects.get(username=self.username)
                self.attributes = ifxuser.__dict__
                logger.debug('Got IfxUser object')
                return True
            except Exception as e:
                logger.error('Unable to get IfxUser %s: %s', self.username, str(e))
                return False
        else:
            logger.debug('Password failed')
            return False

    def __str__(self):
        return self.username

    def attributs(self):
        '''
        Return attributes from IfxUser
        '''
        attributes = {}
        try:
            ifxuser = IfxUser.objects.get(username=self.username)
            for k in ['first_name', 'last_name', 'email', 'username', 'is_active']:
                attributes[k] = getattr(ifxuser, k)
        except Exception as e:
            logger.exception('Unable to find user %s: %s', self.username, str(e))
        return attributes

    def check_radius(self, code):
        '''
        Check 2factor code against RADIUS server
        '''
        # return True
        logger.debug('Checking radius')
        try:
            return radius.authenticate(settings.RADIUS_SECRET, self.username, code, settings.RADIUS_SERVER)
        except Exception as e:
            logger.exception('Unable to authenticate against RADIUS server %s: %s', (settings.RADIUS_SERVER, str(e)))
            return False

    def check_ad(self, password=None):
        '''
        Check username / password against AD


        Tries 6 times to connect, and if it can't fails.
        '''
        # return True
        logger.debug('Checking AD password')
        if password is None or password == '':
            return False
        user = r"rc\%s" % self.username

        # Loop up to 5 times if there is a failure contacting the LDAP server
        dnstry = 0
        maxtries = 2
        while True:
            try:
                ldapurl = '%s:%d' % (settings.AD_SERVER, settings.AD_PORT)
                logger.debug('Initializing LDAP connection to %s' % ldapurl)
                server = Server(ldapurl, connect_timeout=5)
                logger.debug("Attempting to bind")
                conn = Connection(server, user=user, password=password)
                return conn.bind()
            except ldap.LDAPError as e:
                if "Can't contact LDAP server" in str(e) and dnstry < maxtries:
                    logger.info("LDAP server %s unavailable, trying again. %s" % (ldapurl, str(e)))
                    dnstry += 1
                    time.sleep(1)
                else:
                    logger.error("Error connecting to LDAP %s\n%s, %s" % (str(e), settings.AD_SERVER, settings.AD_PORT))
                    return False
