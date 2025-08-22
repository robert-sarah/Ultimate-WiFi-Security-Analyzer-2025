"""
Configuration de l'analyseur WiFi
Fichier de configuration pour les paramètres de l'application
"""

import os

class Config:
    """Configuration principale de l'application"""
    
    # Chemins
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    PYTHON_MODULE_PATH = os.path.join(BASE_DIR, "build", "Release")
    
    # Paramètres WiFi
    SCAN_TIMEOUT = 5000  # ms
    CAPTURE_BUFFER_SIZE = 1024 * 1024  # 1MB
    MAX_PACKETS_DISPLAY = 1000
    
    # Paramètres d'interface
    WINDOW_WIDTH = 1400
    WINDOW_HEIGHT = 900
    REFRESH_RATE = 1000  # ms
    
    # Paramètres de sécurité
    ETHICAL_MODE = True
    AUTHORIZATION_REQUIRED = True
    LOG_ACTIVITIES = True
    
    # Formats de décodage
    DECODING_FORMATS = {
        "ASCII": "ascii",
        "Binaire": "binary", 
        "Hexadécimal": "hex",
        "Brut": "raw"
    }
    
    # Paramètres d'export
    EXPORT_FORMATS = [".txt", ".csv", ".json"]
    DEFAULT_EXPORT_DIR = os.path.join(BASE_DIR, "exports")
    
    # Paramètres de journalisation
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    LOG_LEVEL = "INFO"
    LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
    
    @classmethod
    def create_directories(cls):
        """Créer les répertoires nécessaires"""
        directories = [
            cls.DEFAULT_EXPORT_DIR,
            cls.LOG_DIR,
            cls.PYTHON_MODULE_PATH
        ]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)

class SecurityConfig:
    """Configuration de sécurité et éthique"""
    
    # Avertissements légaux
    LEGAL_WARNINGS = {
        "fr": "Cet outil est destiné à des fins éducatives uniquement. Utilisation autorisée sur vos propres réseaux.",
        "en": "This tool is for educational purposes only. Authorized use on your own networks only."
    }
    
    # Limitations éthiques
    ETHICAL_CONSTRAINTS = [
        "Ne pas capturer de données sensibles sans consentement",
        "Respecter la vie privée des utilisateurs",
        "Utiliser uniquement sur des réseaux autorisés",
        "Documenter toutes les activités de test"
    ]
    
    # Auto-destruction
    SELF_DESTRUCT_ENABLED = True
    SELF_DESTRUCT_TIMEOUT = 300  # secondes
    
    # Vérification d'autorisation
    AUTHORIZATION_CHECK = True
    AUTHORIZATION_FILE = os.path.join(Config.BASE_DIR, "authorization.txt")