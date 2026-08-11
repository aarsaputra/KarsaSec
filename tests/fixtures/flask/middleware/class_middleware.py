class AuthMiddleware:
    def before_request(self):
        pass

class LoggingMiddleware:
    def after_request(self, response):
        return response
