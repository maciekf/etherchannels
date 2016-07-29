from rest_framework.renderers import BrowsableAPIRenderer
from django import forms

class CustomPostFormBrowsableAPIRenderer(BrowsableAPIRenderer):

    def get_rendered_html_form(self, data, view, method, request):
        if method == 'POST':
            return self.get_custom_post_form()
        else:
            return super(CustomPostFormBrowsableAPIRenderer, self).get_rendered_html_form(data, view, method, request)

    def get_custom_post_form(self):
        pass


class CreateChannelForm(forms.Form):
    cid = forms.CharField(label='cid', max_length=70)
    to = forms.CharField(label='to', max_length=70)
    to_hostname = forms.CharField(label='to_hostname', max_length=70)
    to_port = forms.CharField(label='to_port', max_length=70)


class CreateChannelPostFormBrowsableAPIRenderer(CustomPostFormBrowsableAPIRenderer):

    def get_custom_post_form(self):
        return CreateChannelForm().as_p()


class RegisterForm(forms.Form):
    name = forms.CharField(label='name', max_length=70)
    email = forms.CharField(label='email', max_length=70)
    password = forms.CharField(label='password', max_length=70)


class RegisterPostFormBrowsableAPIRenderer(CustomPostFormBrowsableAPIRenderer):

    def get_custom_post_form(self):
        return RegisterForm().as_p()


class BalanceForm(forms.Form):
    balance = forms.CharField(label='balance', max_length=70)


class BalancePostFormBrowsableAPIRenderer(CustomPostFormBrowsableAPIRenderer):

    def get_custom_post_form(self):
        return RegisterForm().as_p()
