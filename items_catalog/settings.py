import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = '/public/app/users/upload'
EXTENSIONS = ['png', 'bmp', 'jpg', 'jpeg', 'gif']


DB = {
    'user': 'DB_USERNAME',
    'password': 'DB_PASSWORD',
    'database': 'DB_NAME',
    'host': 'DB_HOST'  # 127.0.0.1:5432
}
