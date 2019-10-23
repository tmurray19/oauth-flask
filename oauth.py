import json, logging

from rauth import OAuth1Service, OAuth2Service
from flask import current_app, url_for, request, redirect, session

###
# This code is only for Facebook and Twitter
# YouTube has its own OAuth flow
###

class OAuthSignIn(object):
    providers = None

    # This code decides the right credentials to use in the code (Facebook or Twitter)
    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    # Abstract functions
    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name,
                       _external=True)

    # This code determines the provider
    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]

# Initialise OAuth flow service for the Social Media
# Redirect user to the social media for them to login
# Receive the tokens and various info needed for video uploading
# Pass that info to the routes, where it stores that info in the users account on the database
class FacebookSignIn(OAuthSignIn):
    def __init__(self):
        super(FacebookSignIn, self).__init__('facebook')
        self.service = OAuth2Service(
            name='facebook',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://graph.facebook.com/oauth/authorize',
            access_token_url='https://graph.facebook.com/oauth/access_token',
            base_url='https://graph.facebook.com/'
        )
  
    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email publish_pages manage_pages',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None, None

        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url(),
                  },
            decoder=decode_json
        )

        me = oauth_session.get('me?fields=id,email,accounts').json()
        logging.debug("Facebook me information: {}".format(me))
        # Returns ID for user
        # Their email
        # The access token for the first page they own
        # And the ID for the first page they own
        return (
            'facebook$' + me['id'],
            me.get('email'),
            me['accounts']['data'][0].get('access_token'),
            me['accounts']['data'][0].get("id"),
            None
        )


class TwitterSignIn(OAuthSignIn):
    def __init__(self):
        super(TwitterSignIn, self).__init__('twitter')
        self.service = OAuth1Service(
            name='twitter',
            consumer_key=self.consumer_id,
            consumer_secret=self.consumer_secret,
            request_token_url='https://api.twitter.com/oauth/request_token',
            authorize_url='https://api.twitter.com/oauth/authorize',
            access_token_url='https://api.twitter.com/oauth/access_token',
            base_url='https://api.twitter.com/1.1/'
        )

    def authorize(self):
        request_token = self.service.get_request_token(
            params={'oauth_callback': self.get_callback_url()}
        )
        session['request_token'] = request_token
        return redirect(self.service.get_authorize_url(request_token[0]))

    def callback(self):
        request_token = session.pop('request_token')
        if 'oauth_verifier' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            request_token[0],
            request_token[1],
            data={'oauth_verifier': request.args['oauth_verifier']}
        )
        me = oauth_session.get('account/verify_credentials.json').json()

        social_id = 'twitter$' + str(me.get('id'))
        username = me.get('screen_name')
        # Provide twitter username, and OAuth access token and secret
        return social_id, oauth_session.access_token, oauth_session.access_token_secret, None, username

