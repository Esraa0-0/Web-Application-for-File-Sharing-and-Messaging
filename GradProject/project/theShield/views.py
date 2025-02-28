from django.shortcuts import render,redirect
from .models import Users, Messages
import re, os, mimetypes, shutil
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from django.contrib.auth.hashers import check_password, make_password
from django.core.files.storage import default_storage, FileSystemStorage
from django.core.files.base import ContentFile
from django.http import HttpResponse

global user

# Key generation function
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_aes(data, key):
    cipher_aes = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return cipher_aes.nonce, ciphertext, tag

def decrypt_aes(encrypted_data, key):
    nonce, ciphertext, tag = encrypted_data
    cipher_aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data

def encrypt_rsa(aes_key, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_key = cipher_rsa.encrypt(aes_key)
    return enc_key

def decrypt_rsa(enc_key, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(enc_key)
    return decrypted_key

def compute_sha256(data):
    hash_obj = SHA256.new(data)
    return hash_obj.digest()

# Encrypt any file
def encrypt_file(file, output_file, public_key):
    file_data = file.read()  # Read the file content

    # Compute hash of the file
    file_hash = compute_sha256(file_data)

    # Generate AES key and encrypt the file
    aes_key = get_random_bytes(32)
    nonce, ciphertext, tag = encrypt_aes(file_data, aes_key)

    # Encrypt AES key using RSA
    encrypted_aes_key = encrypt_rsa(aes_key, public_key)

    # Save the encrypted file
    with open(output_file, "wb") as enc_file:
        enc_file.write(encrypted_aes_key + nonce + tag + ciphertext + file_hash)

# Decrypt any file
def decrypt_file(input_file, output_file, private_key):
    with open(input_file, "rb") as enc_file:
        file_data = enc_file.read()

    # Extract components
    enc_key = file_data[:256]  # Encrypted AES key (256 bytes for RSA 2048-bit key)
    nonce = file_data[256:272]  # AES nonce (16 bytes)
    tag = file_data[272:288]  # AES tag (16 bytes)
    ciphertext = file_data[288:-32]  # Encrypted file content
    original_hash = file_data[-32:]  # Original hash value (SHA-256 is 32 bytes)

    # Decrypt AES key using RSA
    aes_key = decrypt_rsa(enc_key, private_key)

    # Decrypt file content using AES
    decrypted_data = decrypt_aes((nonce, ciphertext, tag), aes_key)

    # Compute hash of decrypted data
    decrypted_hash = compute_sha256(decrypted_data)

    # Save decrypted data
    with open(output_file, "wb") as dec_file:
        dec_file.write(decrypted_data)

    # Compare hashes to verify file integrity
    if decrypted_hash == original_hash:
        print("File integrity verified: Safe.")
    else:
        print("File integrity compromised: Manipulated.")

def decrypt_file_to_memory(input_file, aes_key, private_key):
    with open(input_file, "rb") as enc_file:
        file_data = enc_file.read()

    # Extract components
    enc_key = file_data[:256]  # Encrypted AES key (256 bytes for RSA 2048-bit key)
    nonce = file_data[256:272]  # AES nonce (16 bytes)
    tag = file_data[272:288]  # AES tag (16 bytes)
    ciphertext = file_data[288:-32]  # Encrypted file content
    original_hash = file_data[-32:]  # Original hash value (SHA-256 is 32 bytes)

    # Decrypt AES key using RSA
    aes_key = decrypt_rsa(enc_key, private_key)

    # Decrypt file content using AES
    decrypted_data = decrypt_aes((nonce, ciphertext, tag), aes_key)

    # Verify integrity
    decrypted_hash = compute_sha256(decrypted_data)
    if decrypted_hash != original_hash:
        raise ValueError("File integrity compromised")

    return decrypted_data

# Create your views here.
def home(request):
    return render(request, 'theShield/main.html')

def login_signup(request):
    if request.method == 'POST':
        form_type = request.POST.get('form_type')  # Check which form was submitted

        if form_type == 'login':
            username = request.POST.get('username')
            password = request.POST.get('password')
            
            # Validate username
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                return render(request, 'theShield/login_signup.html', {'error_message2': 'The credentials provided are invalid', 'form_type': 'login'})

            # Validate password
            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$', password):
                return render(request, 'theShield/login_signup.html', {'error_message2': 'The credentials provided are invalid', 'form_type': 'login'})
            
            try:
                user = Users.objects.get(username=username)
                if check_password(password, user.password):  
                    request.session['username'] = user.username
                    return redirect('user')
                else:
                    return render(request, 'theShield/login_signup.html', {
                        'error_message2': 'The credentials provided are invalid',
                        'form_type': 'login'
                    })
            except Users.DoesNotExist:
                return render(request, 'theShield/login_signup.html', {
                    'error_message2': 'The credentials provided are invalid',
                    'form_type': 'login'
                })

        elif form_type == 'signup':
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')

            # Validate username
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                return render(request, 'theShield/login_signup.html', {
                    'error_message1': 'Username can only contain letters, numbers, and underscores _',
                    'form_type': 'signup'
                })

            # Validate password
            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$', password):
                return render(request, 'theShield/login_signup.html', {
                    'error_message1': 'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character',
                    'form_type': 'signup'
                })

            # Check if username or email is already in use
            if Users.objects.filter(username=username).exists():
                return render(request, 'theShield/login_signup.html', {
                    'error_message1': 'Username is already taken!',
                    'form_type': 'signup'
                })
            elif Users.objects.filter(email=email).exists():
                return render(request, 'theShield/login_signup.html', {
                    'error_message1': 'Email is already in use!',
                    'form_type': 'signup'
                })

            # Generate keys and save user
            while True:
                private_key, public_key = generate_keys()
                if not Users.objects.filter(private_key=private_key, public_key=public_key).exists():
                    break

            hashed_password = make_password(password)
            new_user = Users(username=username, email=email, password=hashed_password, private_key=private_key, public_key=public_key)
            new_user.save()

            return render(request, 'theShield/login_signup.html', {
                'success_message': 'Account created successfully!',
                'form_type': 'login'
            })

    return render(request, 'theShield/login_signup.html')

def user(request):
    username = request.session.get('username')

    if not username:
        return redirect('login_signup')

    user = Users.objects.get(username=username)
    messages = Messages.objects.filter(recipient=user)
    decrypted_message = None
    response = None
    file_url = None  

    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'encrypt':
            recipient_name = request.POST.get('recipient')
            try:
                recipient = Users.objects.get(username=recipient_name)
            except Users.DoesNotExist:
                return render(request, 'theShield/user.html', {
                    'user': user,
                    'messages': messages,
                    'error_message1': 'Recipient not found.'
                })

            message = request.POST.get('message', '').encode()
            file = request.FILES.get('attachment')

            aes_key = get_random_bytes(32)
            encrypted_aes_key = encrypt_rsa(aes_key, recipient.public_key)

            if message:
                nonce, ciphertext, tag = encrypt_aes(message, aes_key)
                msg_hash = compute_sha256(message)
                hex_hash = msg_hash.hex()  # Convert the hash to a string for storage
                
            new_message = Messages(
                sender=user,
                recipient=recipient,
                ciphertext=ciphertext if message else None,
                nonce=nonce if message else None,
                tag=tag if message else None,
                attachment=None,
                key=encrypted_aes_key if message or file else None,
                hash=hex_hash if message else None
            )
            new_message.save()  # Save first to generate the `message_id`.

            if file:
                # Ensure the directory exists
                directory_path = os.path.join(default_storage.location, f"files/{new_message.message_id}")
                os.makedirs(directory_path, exist_ok=True)

                # Define the file path and save the encrypted file
                file_path = f"files/{new_message.message_id}/{file.name}"
                file_data = file.read()
                encrypt_file(ContentFile(file_data), default_storage.path(file_path), recipient.public_key)
                new_message.attachment.name = file_path

            new_message.save()

        elif form_type == 'decrypt':
            message_id = request.POST.get('message_id')
            try:
                encrypted_message = Messages.objects.get(message_id=message_id)
            except Messages.DoesNotExist:
                return render(request, 'theShield/user.html', {
                    'user': user,
                    'messages': messages,
                    'error_message2': 'Message not found.'
                })

            decrypted_aes_key = decrypt_rsa(encrypted_message.key, user.private_key)

            if encrypted_message.ciphertext:
                nonce = encrypted_message.nonce
                ciphertext = encrypted_message.ciphertext
                tag = encrypted_message.tag
                    
                decrypted_message = decrypt_aes((nonce, ciphertext, tag), decrypted_aes_key)
                msg_hash = compute_sha256(decrypted_message)
                stored_hash = bytes.fromhex(encrypted_message.hash)  # Convert stored hex hash back to bytes

                if msg_hash != stored_hash:
                    return render(request, 'theShield/user.html', {
                        'user': user,
                        'messages': messages,
                        'decrypted_message': decrypted_message.decode(),
                        'error_message2': 'Message integrity compromised.'
                    })
                    
            if encrypted_message.attachment:
                # Get the file path from the FileField
                encrypted_file_path = default_storage.path(encrypted_message.attachment.name)
    
                # Get the file name for response
                file_name = os.path.basename(encrypted_file_path)
    
                try:
                    # Decrypt the file content to memory
                    decrypted_file = decrypt_file_to_memory(encrypted_file_path, decrypted_aes_key, user.private_key)
        
                    # Prepare the response with decrypted content
                    response = HttpResponse(decrypted_file, content_type=mimetypes.guess_type(file_name)[0])
                    response['Content-Disposition'] = f'attachment; filename="{file_name}"'
                    
                    # Save the decrypted file to the file system
                    fs = FileSystemStorage()
                    file_name = f"decrypted_{encrypted_message.attachment.name}"
                    file_url = fs.url(fs.save(file_name, ContentFile(decrypted_file)))
                    
                except Exception as e:
                    return render(request, 'theShield/user.html', {
                        'user': user,
                        'messages': messages,
                        'error_message2': f'Error decrypting file: {str(e)}'
                     })

            encrypted_message.is_read=True
            encrypted_message.save()
            
            shutil.rmtree(os.path.join(default_storage.location, f"files/{encrypted_message.message_id}"))
            Messages.objects.filter(is_read=True).delete()

            return render(request, 'theShield/user.html', {
                'user': user,
                'messages': messages,
                'decrypted_message': decrypted_message.decode() if encrypted_message.ciphertext else None,
                'file': 'file is ready to download!' if encrypted_message.attachment else None,
                'file_url': file_url if encrypted_message.attachment else None,
                'show_content2': True,
                }) 

    return render(request, 'theShield/user.html', {'user': user, 'messages': messages})

def logout(request):
    files = r"C:\Users\user\University\Graduation Project 2\GradProject\project\media\decrypted_files"
    if os.path.isdir(files):
        shutil.rmtree(files)
    
    request.session.flush()  # Clear the session
    return redirect('login_signup')
