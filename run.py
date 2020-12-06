from app.app import create_app

APP = create_app('default')
APP_CTX = APP.app_context()
APP_CTX.push()

if __name__ == '__main__':
    APP.run()
