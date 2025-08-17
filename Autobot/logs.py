import logging

def setup_logging():
    logging.basicConfig(
        filename='phishguard.log' 'smishguard.log' 'vishguard.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s'
    )