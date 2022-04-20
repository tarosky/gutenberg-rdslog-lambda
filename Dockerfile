FROM public.ecr.aws/lambda/python:3.9

RUN yum install -y https://repo.percona.com/yum/percona-release-latest.noarch.rpm
RUN yum install -y percona-toolkit

COPY requirements.txt  .
RUN pip3 install -r requirements.txt --target "${LAMBDA_TASK_ROOT}"

COPY index.py ${LAMBDA_TASK_ROOT}

CMD [ "index.lambda_handler" ]
