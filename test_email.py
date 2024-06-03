import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
from config import EMAIL_ADDRESS, EMAIL_PASSWORD, SMTP_SERVER, SMTP_PORT, DOMAIN, AUTH_METHOD, ENABLE_STARTTLS_AUTO, \
    OPENSSL_VERIFY_MODE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EMAIL_USER = 'deliciasdaauzi@gmail.com'
EMAIL_PASS = '@Evt.2024'

def send_email(file_content):
    logger.info("Preparando o e-mail para envio.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = "HTML Content Email"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = "lucassilva.eq@gmail.com"  # Você pode mudar isso para o e-mail do destinatário

    try:
        logger.info("Preparando o e-mail para envio.")
        logger.info("Tentando conectar ao servidor SMTP.")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.set_debuglevel(1)  # Ativar modo de depuração
        logger.info("Conexão estabelecida, iniciando TLS.")
        server.starttls()
        logger.info("Fazendo login no servidor SMTP.")
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        logger.info("Enviando o e-mail.")
        server.sendmail(EMAIL_ADDRESS, 'lucassilva.eq@gmail.com', msg.as_string())
        logger.info("E-mail enviado com sucesso!")
        server.quit()
    except Exception as e:
        logger.error(f"Erro ao enviar e-mail: {e}")

if __name__ == "__main__":
    send_email("Conteúdo de teste do e-mail.")
