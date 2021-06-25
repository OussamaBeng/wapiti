from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import MEDIUM_LEVEL, _
from wapitiCore.definitions.http_post import NAME


# This module check the security of transported credentials of login forms
class mod_http_post(Attack):
    """Check if credentials are transported on an encrypted channel."""
    name = "http_post"

    async def must_attack(self, request: Request):
        # We leverage the fact that the crawler will fill password entries with a known placeholder
        if "Letm3in_" not in request.encoded_data + request.encoded_params:
            return False

        # We may want to remove this but if not available fallback to target URL
        if not request.referer:
            return False

        return True

    async def attack(self, request: Request):
        try:
            page = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        login_form, username_field, password_field = page.find_login_form()
        if not login_form:
            return

        self.finished = True

        if "http://" in login_form.url:
            self.log_red(_("Credentials transported over an Unencrypted Channel on : {0}"), login_form.url)

            await self.add_vuln_medium(
                request_id=request.path_id,
                category=NAME,
                request=request,
                info=_("Credentials transported over an Unencrypted Channel on :  {0}").format(login_form.url)
            )
