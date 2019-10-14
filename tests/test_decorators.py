"""django_ariadne_jwt_auth decorators tests"""
import ariadne
from dataclasses import dataclass
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import TestCase
from starlette.requests import Request as StarletteRequest
from unittest.mock import Mock
from django_ariadne_jwt.backends import JSONWebTokenBackend
from django_ariadne_jwt.decorators import login_required
from django_ariadne_jwt.middleware import JSONWebTokenMiddleware
from django_ariadne_jwt import exceptions


HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"


@dataclass
class InfoObject(object):
    context: HttpRequest


def resolve_noop(*args, **kwargs):
    pass


class DecoratorsTestCase(TestCase):
    """Tests for the JWT middleware"""

    def setUp(self):
        User = get_user_model()

        self.user_data = {
            User.USERNAME_FIELD: "test_user",
            "password": "lame_password",
        }

        self.user = User.objects.create(**self.user_data)
        self.user.set_password(self.user_data["password"])
        self.user.save()

    def test_raises_on_no_request(self):
        # This is a state we shouldn't get into, but just in case
        with self.assertRaises(exceptions.ImproperlyConfigured) as cm:
            info = InfoObject(context={})
            login_required(resolve_noop)(None, info)
        self.assertEqual(str(cm.exception), "No request object found.")

    def test_raises_exception_if_no_user_is_present(self):
        with self.assertRaises(exceptions.ImproperlyConfigured) as cm:
            info = InfoObject(context={"request": HttpRequest()})
            login_required(resolve_noop)(None, info)
        self.assertEqual(
            str(cm.exception),
            "No user found on request. Verify that JSONWebTokenMiddleware "
            "is properly configured.",
        )

    def test_returns_wrapped_resolver_on_success(self):
        expected_return = object()

        def resolver(*args, **kwargs):
            return expected_return

        request = HttpRequest()
        request.user = Mock(is_authenticated=True)
        info = InfoObject(context={"request": request})

        self.assertEqual(login_required(resolver)(None, info), expected_return)

    def test_raises_loginrequired_on_unauthenticated_user(self):
        request = HttpRequest()
        request.user = Mock(is_authenticated=False)
        info = InfoObject(context={"request": request})

        with self.assertRaises(exceptions.LoginRequiredError):
            login_required(resolve_noop)(None, info)

    def test_can_handle_starlette_request(self):
        expected_return = object()

        def resolver(*args, **kwargs):
            return expected_return

        user = Mock(is_authenticated=True)
        request = StarletteRequest(scope={"type": "http", "user": user})
        info = InfoObject(context={"request": request})

        self.assertEqual(login_required(resolver)(None, info), expected_return)

    def test_can_handle_unauthenticated_starlette_request(self):
        user = Mock(is_authenticated=False)
        request = StarletteRequest(scope={"type": "http", "user": user})
        info = InfoObject(context={"request": request})

        with self.assertRaises(exceptions.LoginRequiredError):
            login_required(resolve_noop)(None, info)

    def test_login_required_decorator_without_valid_token(self):
        """Tests the login required decorator called without valid token"""
        type_definitions = ariadne.gql(
            """
            type Query {
                me: String!
                mustfail: String!
            }
        """
        )

        query_type = ariadne.QueryType()

        resolve_me = Mock(return_value="Me!")
        query_type.set_field("me", resolve_me)

        resolve_mustfail = Mock(return_value="FAIL!")
        decorated_resolve_mustfail = Mock(
            wraps=login_required(resolve_mustfail)
        )
        query_type.set_field("mustfail", decorated_resolve_mustfail)

        schema = ariadne.make_executable_schema(
            [type_definitions], [query_type]
        )

        middleware = [JSONWebTokenMiddleware()]

        request = HttpRequest()

        settings = {
            "AUTHENTICATION_BACKENDS": (
                "django_ariadne_jwt.backends.JSONWebTokenBackend",
                "django.contrib.auth.backends.ModelBackend",
            )
        }

        with self.settings(**settings):
            success, result = ariadne.graphql_sync(
                schema,
                {
                    "query": """
                    query {
                        me
                        mustfail
                    }
                    """
                },
                context_value={"request": request},
                middleware=middleware,
            )

            self.assertTrue(resolve_me.called)
            self.assertFalse(resolve_mustfail.called)

            self.assertIsNotNone(result)
            self.assertIn("errors", result)

            test_field_error_found = False

            for error_data in result["errors"]:
                if "mustfail" in error_data["path"]:
                    test_field_error_found = True

            self.assertTrue(test_field_error_found)
