class ClientError(Exception):
    """Base of exceptions raised for 4xx errors."""

    def __init__(self, msg=None):
        if msg is None:
            msg = f'Bad Request'
        super().__init__(msg)


class ServerError(Exception):
    """Base of exceptions raised for 500 errors."""

    def __init__(self, msg=None):
        if msg is None:
            msg = 'Server error'
        super().__init__(msg)


class MissingRequiredParamError(ClientError):
    def __init__(self, params, msg=None):
        if msg is None:
            msg = f'Missing required param(s): {params}'
        super().__init__(msg)


class EmptyParamError(ClientError):
    def __init__(self, params, msg=None):
        if msg is None:
            msg = f'Missing values for param(s): {params}'
        super().__init__(msg)


class InvalidParamValueError(ClientError):
    def __init__(self, param, param_values, supported_values, msg=None):
        if msg is None:
            msg = f'Invalid value(s): {param_values} for param: {param}. ' \
                  f'Valid values are: {supported_values}.'
        super().__init__(msg)


class UnsupportedValueError(ClientError):
    def __init__(self, param, value, secondary_param, secondary_value):
        msg = f'Unsupported value: {value} for param: {param} when ' \
              f'{secondary_param}={secondary_value}'
        super().__init__(msg)


class UnsupportedParamError(ClientError):
    def __init__(self, param):
        msg = f'Unsupported param(s): {param}'
        super().__init__(msg)


class IncorrectDecryptionError(ClientError):
    def __init__(self):
        msg = f'Token could not be decrypted'
        super().__init__(msg)
