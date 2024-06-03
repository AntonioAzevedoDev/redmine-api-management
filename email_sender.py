import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import EMAIL_ADDRESS, EMAIL_PASSWORD, SMTP_SERVER, SMTP_PORT, DOMAIN, AUTH_METHOD, ENABLE_STARTTLS_AUTO, \
    OPENSSL_VERIFY_MODE
import logging
import re

from test_email import logger


def send_email(html_content, recipient_email, project_name, user_name):
    logger.info("Preparando o e-mail para envio.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"Relatório de horas - {user_name} - {project_name}"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email  # Usa o destinatário dinâmico
    part = MIMEText(html_content, 'html')
    msg.attach(part)
    try:
        logger.info("Tentando conectar ao servidor SMTP.")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.set_debuglevel(1)  # Ativar modo de depuração
        logger.info("Conexão estabelecida, iniciando TLS.")
        server.starttls()
        logger.info("Fazendo login no servidor SMTP.")
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        logger.info("Enviando o e-mail.")
        server.sendmail(EMAIL_ADDRESS, recipient_email, msg.as_string())
        logger.info("E-mail enviado com sucesso!")
        server.quit()
    except Exception as e:
        logger.error(f"Erro ao enviar e-mail: {e}")
