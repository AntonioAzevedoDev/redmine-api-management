from venv import logger

from app import API_URL
from email_sender import send_email


def send_email_task(file_content, recipient_emails, project_name, user_id, user_name):
    logger.info("Tarefa de envio de e-mail iniciada.")
    try:
        logger.info("Chamando função send_email com o seguinte conteúdo:")
        logger.info(file_content)
        for email in recipient_emails:
            # Adiciona o link de referência ao corpo do email
            link = f"{API_URL}relatorio_horas/{user_id}"
            email_content = f"{file_content}\n\nPara visualizar as entradas de tempo, acesse o link: {link}"
            send_email(email_content, email.strip(), project_name, user_name)
            logger.info(f"Enviando e-mail para: {email.strip()}")
        logger.info("E-mails enviados com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao enviar e-mails: {e}")