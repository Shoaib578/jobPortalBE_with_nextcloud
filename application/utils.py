from werkzeug.utils import secure_filename
import os
import hashlib
from application import app
import requests
import owncloud

def generate_hash(filename):
    # Use hashlib to create a SHA-256 hash of the filename
    hash_object = hashlib.sha256(filename.encode())
    return hash_object.hexdigest()


def save_file(file, file_type):
    original_filename = secure_filename(file.filename)
    
    # Generate a hash for the filename
    filename_hash = generate_hash(original_filename)

    # Append the hash to the original filename
    hashed_filename = f"{filename_hash}_{original_filename}"

    folder = os.path.join(app.root_path, "static/" + file_type + "/")
    file_path = os.path.join(folder, hashed_filename)

    try:
        file.save(file_path)
        return hashed_filename, file_path
    except Exception as e:
        return False, str(e)



def save_logo(file,file_type):
    folder = os.path.join(app.root_path, "static/" + file_type + "/")
    file_path = os.path.join(folder, 'logo.png')
    try:
        file.save(file_path)
        return True, 'logo.png'
    except Exception as e:
        return False, str(e)

def remove_file(file):
    
    
    try:
        os.remove(file)
        return True
    except:
        return False





oc = owncloud.Client('https://host28.ssl-net.net/knowledgecheckr_com/cloud/app/')

oc.login(os.getenv('nextcloud_username'), os.getenv('nextcloud_password'))


def make_dir(dir_name):
    directory = oc.mkdir(f'PowerdriveApp/{dir_name}')
    return directory


def get_file_link(path):
    link_info = oc.share_file_with_link(path)
    link = link_info.get_link()
    return link


def delete_file(path):
    try:
         oc.delete(path)
         return True
    except Exception as e:
        print(e)
        return False


def upload_file(path,file):
    try:
        saved_file = save_file(file,'uploads')
        put_file = oc.put_file(f'{path}{saved_file[0]}',saved_file[1])
        remove_file(saved_file[1])
        return saved_file[0]

    except Exception as e:
        print(e)
        return False

