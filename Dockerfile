FROM public.ecr.aws/lambda/python:3.9

RUN yum install -y https://repo.percona.com/yum/percona-release-latest.noarch.rpm
RUN yum install -y percona-toolkit

COPY index.py ${LAMBDA_TASK_ROOT}

CMD [ "index.lambda_handler" ]
