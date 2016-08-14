#!/usr/bin/env python
# -*- coding: utf-8 -*-
from gluon.validators import Validator
import re

# CONTAINS CLASSES FOR CUSTOM INPUT VALIDATION

class IS_STRONG_PASSWORD(Validator):
    def __init__(self, error_message='Weak password. See details on what makes a strong password.'):
        self.error_message = error_message

    def __call__(self, value):
        if len(value) >= 8 and re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            return (True, None)
        else:
            return (False, self.error_message)

'''
class IS_SAME(Validator):
    def __init__(self, other, error_message='New Password and Confirm Password do not match.'):
        self.error_message = error_message
        self.other = other

    def __call__(self, value):
        if self.other == value: return (True, None)
        else: return (False, self.error_message) '''
