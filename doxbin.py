#!/usr/bin/env python3
"""
DoxBin-Terminal: A terminal-based document sharing and storage utility
Designed for Kali Linux and Ubuntu
"""

import os
import sys
import json
import argparse
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import shutil

class DoxBinTerminal:
    def __init__(self):
        self.home_dir = Path.home()
        self.doxbin_dir = self.home_dir / '.doxbin'
        self.db_path = self.doxbin_dir / 'doxbin.db'
        self.config_path = self.doxbin_dir / 'config.json'
        
        # Create directories if they don't exist
        self.doxbin_dir.mkdir(exist_ok=True)
        
        # Initialize database
        self._init_db()
        
        # Load or create config
        self._load_config()
    
    def _init_db(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Documents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                content BLOB NOT NULL,
                encrypted BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                password_hash TEXT,
                views INTEGER DEFAULT 0,
                max_views INTEGER,
                description TEXT
            )
        ''')
        
        # Access logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id TEXT NOT NULL,
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                FOREIGN KEY(doc_id) REFERENCES documents(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_config(self):
        """Load or create configuration"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                'encryption_key': Fernet.generate_key().decode(),
                'server_url': 'http://localhost:8080',
                'default_expiry_hours': 24,
                'default_encryption': True
            }
            self._save_config()
    
    def _save_config(self):
        """Save configuration to file"""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def _generate_document_id(self) -> str:
        """Generate a unique document ID"""
        return secrets.token_urlsafe(12)
    
    def _derive_key(self, password: str, salt: bytes = None) -> tuple:
        """Derive encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def _encrypt_content(self, content: bytes, password: Optional[str] = None) -> tuple:
        """Encrypt content using Fernet"""
        if password:
            key, salt = self._derive_key(password)
        else:
            key = self.config['encryption_key'].encode()
            salt = b''
        
        cipher = Fernet(key)
        encrypted = cipher.encrypt(content)
        return encrypted, salt
    
    def _decrypt_content(self, encrypted_content: bytes, password: Optional[str] = None, salt: bytes = b'') -> bytes:
        """Decrypt content"""
        if password:
            key, _ = self._derive_key(password, salt)
        else:
            key = self.config['encryption_key'].encode()
        
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_content)
    
    def upload_file(self, filepath: str, password: Optional[str] = None, 
                   expiry_hours: Optional[int] = None, max_views: Optional[int] = None,
                   description: str = '') -> str:
        """Upload a file to DoxBin"""
        filepath = Path(filepath)
        
        if not filepath.exists():
            print(f"❌ Error: File '{filepath}' not found")
            return None
        
        if not filepath.is_file():
            print(f"❌ Error: '{filepath}' is not a file")
            return None
        
        try:
            # Read file content
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Encrypt content
            encrypted_content, salt = self._encrypt_content(content, password)
            
            # Generate document ID
            doc_id = self._generate_document_id()
            
            # Calculate expiry time
            if expiry_hours is None:
                expiry_hours = self.config['default_expiry_hours']
            
            expires_at = datetime.now() + timedelta(hours=expiry_hours)
            
            # Hash password if provided
            password_hash = hashlib.sha256(password.encode()).hexdigest() if password else None
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO documents (id, filename, content, encrypted, expires_at, password_hash, max_views, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (doc_id, filepath.name, encrypted_content, 1, expires_at, password_hash, max_views, description))
            
            # Store salt if password was used
            if password:
                with open(self.doxbin_dir / f'{doc_id}.salt', 'wb') as f:
                    f.write(salt)
            
            conn.commit()
            conn.close()
            
            print(f"\n✅ File uploaded successfully!")
            print(f"📋 Document ID: {doc_id}")
            print(f"📁 Filename: {filepath.name}")
            print(f"📏 Size: {len(content)} bytes")
            print(f"🔐 Encrypted: Yes")
            if password:
                print(f"🔑 Protected with password")
            print(f"⏰ Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
            if max_views:
                print(f"👁️  Max views: {max_views}")
            
            return doc_id
        
        except Exception as e:
            print(f"❌ Error uploading file: {e}")
            return None
    
    def download_file(self, doc_id: str, password: Optional[str] = None, 
                     output_path: Optional[str] = None) -> bool:
        """Download and decrypt a document"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT filename, content, password_hash, expires_at, views, max_views FROM documents WHERE id = ?', (doc_id,))
            result = cursor.fetchone()
            
            if not result:
                print(f"❌ Error: Document '{doc_id}' not found")
                return False
            
            filename, encrypted_content, password_hash, expires_at, views, max_views = result
            
            # Check expiry
            if expires_at:
                if datetime.fromisoformat(expires_at) < datetime.now():
                    print(f"❌ Error: Document has expired")
                    return False
            
            # Check max views
            if max_views and views >= max_views:
                print(f"❌ Error: Maximum views reached for this document")
                return False
            
            # Check password
            if password_hash:
                if not password:
                    password = input("🔐 Document is password protected. Enter password: ")
                
                if hashlib.sha256(password.encode()).hexdigest() != password_hash:
                    print(f"❌ Error: Incorrect password")
                    return False
                
                # Load salt
                salt_path = self.doxbin_dir / f'{doc_id}.salt'
                salt = b''
                if salt_path.exists():
                    with open(salt_path, 'rb') as f:
                        salt = f.read()
            else:
                salt = b''
            
            # Decrypt content
            decrypted_content = self._decrypt_content(encrypted_content, password, salt)
            
            # Determine output path
            if output_path is None:
                output_path = Path.cwd() / filename
            else:
                output_path = Path(output_path)
            
            # Write decrypted content to file
            with open(output_path, 'wb') as f:
                f.write(decrypted_content)
            
            # Update view count
            cursor.execute('UPDATE documents SET views = views + 1 WHERE id = ?', (doc_id,))
            conn.commit()
            conn.close()
            
            print(f"\n✅ File downloaded successfully!")
            print(f"📁 Saved to: {output_path}")
            print(f"📏 Size: {len(decrypted_content)} bytes")
            
            return True
        
        except Exception as e:
            print(f"❌ Error downloading file: {e}")
            return False
    
    def list_documents(self) -> None:
        """List all stored documents"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, filename, created_at, expires_at, views, max_views, password_hash, description
                FROM documents
                ORDER BY created_at DESC
            ''')
            
            documents = cursor.fetchall()
            conn.close()
            
            if not documents:
                print("📭 No documents stored")
                return
            
            print("\n" + "="*100)
            print(f"{'ID':<15} {'Filename':<25} {'Created':<20} {'Expires':<20} {'Views':<8} {'Protected':<10}")
            print("="*100)
            
            for doc in documents:
                doc_id, filename, created_at, expires_at, views, max_views, password_hash, description = doc
                
                # Check if expired
                if expires_at and datetime.fromisoformat(expires_at) < datetime.now():
                    status = "❌ EXPIRED"
                else:
                    status = "✅ Active"
                
                protected = "🔐 Yes" if password_hash else "❌ No"
                view_count = f"{views}" if not max_views else f"{views}/{max_views}"
                
                print(f"{doc_id:<15} {filename:<25} {created_at:<20} {expires_at:<20} {view_count:<8} {protected:<10}")
            
            print("="*100 + "\n")
        
        except Exception as e:
            print(f"❌ Error listing documents: {e}")
    
    def delete_document(self, doc_id: str) -> bool:
        """Delete a document"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
            
            if cursor.rowcount == 0:
                print(f"❌ Error: Document '{doc_id}' not found")
                return False
            
            # Delete salt file if exists
            salt_path = self.doxbin_dir / f'{doc_id}.salt'
            if salt_path.exists():
                salt_path.unlink()
            
            conn.commit()
            conn.close()
            
            print(f"✅ Document '{doc_id}' deleted successfully")
            return True
        
        except Exception as e:
            print(f"❌ Error deleting document: {e}")
            return False
    
    def show_document_info(self, doc_id: str) -> None:
        """Show detailed information about a document"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, filename, created_at, expires_at, views, max_views, password_hash, description
                FROM documents WHERE id = ?
            ''', (doc_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                print(f"❌ Error: Document '{doc_id}' not found")
                return
            
            doc_id, filename, created_at, expires_at, views, max_views, password_hash, description = result
            
            print(f"\n📋 Document Information")
            print("="*50)
            print(f"ID: {doc_id}")
            print(f"Filename: {filename}")
            print(f"Created: {created_at}")
            print(f"Expires: {expires_at if expires_at else 'Never'}")
            print(f"Views: {views if not max_views else f'{views}/{max_views}'}")
            print(f"Password Protected: {'Yes 🔐' if password_hash else 'No ❌'}")
            print(f"Description: {description if description else 'N/A'}")
            print("="*50 + "\n")
        
        except Exception as e:
            print(f"❌ Error retrieving document info: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='DoxBin-Terminal: Secure document sharing and storage for Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  doxbin upload myfile.txt                     # Upload a file
  doxbin upload secret.zip --password mysecret # Upload with password
  doxbin upload doc.pdf --expiry 48             # Upload with 48 hour expiry
  doxbin download ABC123DEF456                 # Download a document
  doxbin list                                  # List all documents
  doxbin info ABC123DEF456                     # Show document info
  doxbin delete ABC123DEF456                   # Delete a document
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload a file')
    upload_parser.add_argument('file', help='File to upload')
    upload_parser.add_argument('--password', '-p', help='Password protect the document')
    upload_parser.add_argument('--expiry', '-e', type=int, default=24, help='Expiry time in hours (default: 24)')
    upload_parser.add_argument('--max-views', '-m', type=int, help='Maximum number of views')
    upload_parser.add_argument('--description', '-d', default='', help='Document description')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download a document')
    download_parser.add_argument('doc_id', help='Document ID')
    download_parser.add_argument('--password', '-p', help='Password for protected documents')
    download_parser.add_argument('--output', '-o', help='Output file path')
    
    # List command
    subparsers.add_parser('list', help='List all documents')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show document information')
    info_parser.add_argument('doc_id', help='Document ID')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a document')
    delete_parser.add_argument('doc_id', help='Document ID')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    doxbin = DoxBinTerminal()
    
    if args.command == 'upload':
        doxbin.upload_file(
            args.file,
            password=args.password,
            expiry_hours=args.expiry,
            max_views=args.max_views,
            description=args.description
        )
    
    elif args.command == 'download':
        doxbin.download_file(args.doc_id, password=args.password, output_path=args.output)
    
    elif args.command == 'list':
        doxbin.list_documents()
    
    elif args.command == 'info':
        doxbin.show_document_info(args.doc_id)
    
    elif args.command == 'delete':
        doxbin.delete_document(args.doc_id)

if __name__ == '__main__':
    main()
