import ets.ets_certmanager_logs_parser_v2 as l_parser
import argparse
import logger_module
import progressbar
from datetime import datetime
from ets.ets_mysql_lib import MysqlConnection as mc, NULL, value_former
from os.path import normpath, join
from queries import *
from config import *

PROGNAME = 'Crypto data to bd parser v2'
DESCRIPTION = '''Скрипт для импорта данных из файлов криптоменеджера в базу данных'''
VERSION = '2.0'
AUTHOR = 'Belim S.'
RELEASE_DATE = '2018-08-30'

type_by_number = {1: 'mroot', 2: 'mca', 3: 'crl'}

tmp_dir = normpath(tmp_dir)
d_server_list = 1, 2, 4, 5
d_storage_list = 'mroot', 'mca', 'crl'
d_storage_numbers = range(1, 4)
d_minutes = 0
d_insert_datetime = datetime.now()

u_server_list = []
u_storage_list = []


def show_version():
    print(PROGNAME, VERSION, '\n', DESCRIPTION, '\nAuthor:', AUTHOR, '\nRelease date:', RELEASE_DATE)


# обработчик параметров командной строки
def create_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-v', '--version', action='store_true',
                        help="Показать версию программы")

    parser.add_argument('-u', '--update', action='store_true',
                        help='''Обновить записи в базе данных.
                        Аргументы:
                        --server - обновить для указанного сервера (необязательный);
                        --file - обновить для указанного типа файла (необязательный);
                        --number - обновить для указанного типа файла (по номеру, необязательный)''')

    parser.add_argument('-r', '--remove', action='store_true',
                        help='''Удалить устаревшие записи из базы данных.
                        Аргументы:
                        --server - удалить для указанного сервера (необязательный),
                        --minutes - за указанное количество минут (по умолчанию 0, необязательный)''')

    parser.add_argument('-s', '--server', type=int, choices=d_server_list,
                        help="Установить номер сервера")

    parser.add_argument('-i', '--file', type=str, choices=d_storage_list,
                        help="Установить тип файла (строковый)")

    parser.add_argument('-n', '--number', type=int, choices=d_storage_numbers,
                        help="Установить тип файла (числовой)")

    parser.add_argument('-m', '--minutes', type=int,
                        help="Установить количество минут")

    return parser


def insert_worker(server, storage):
    """Функция вставки данных в БД по конкретному серверу и хранилищу"""
    types = {'mroot': {'file': 'mRoot_%s.txt' % server, 'storage_num': 1},
             'mca': {'file': 'mCA_%s.txt' % server, 'storage_num': 2},
             'crl': {'file': 'CRL_%s.txt' % server, 'storage_num': 3}}

    # создаем подключение к нужной бд
    cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
    cn.connect()

    def insert_func(ins_rec):
        """Функция вставки записи в БД"""
        if c_file_type == 'CERT':
            subj_key_id = ins_rec.subj_key_id if not ins_rec.subj_key_id == 'UNKNOWN' else None
            d_insert = {'SubjKeyID': subj_key_id,
                        'Subject': ins_rec.subject,
                        'Issuer': ins_rec.issuer,
                        'Serial': ins_rec.serial,
                        'SHA1 Hash': ins_rec.sha1hash,
                        'Signature Algorithm': ins_rec.signature_algorithm,
                        'PrivateKey Link': ins_rec.private_key_link,
                        'PublicKey Algorithm': ins_rec.public_key_algorithm,
                        'Not valid before': ins_rec.not_valid_before,
                        'Not valid after': ins_rec.not_valid_after}
        else:
            auth_key_id = ins_rec.auth_key_id if not ins_rec.auth_key_id == 'UNKNOWN' else None
            d_insert = {'AuthKeyID': auth_key_id,
                        'Issuer': ins_rec.issuer,
                        'ThisUpdate': ins_rec.this_update,
                        'NextUpdate': ins_rec.next_update}

        # добавляем оставшиеся поля
        d_insert['storage_num'] = types[storage]['storage_num']
        d_insert['storage_name'] = storage
        d_insert['server'] = server
        d_insert['datetime'] = d_insert_datetime

        # адаптируем поля для вставки
        for key in d_insert.keys():
            if not d_insert[key]:
                d_insert[key] = NULL
            else:
                d_insert[key] = value_former(d_insert[key])

        # вставляем запись в бд
        cn.execute_query(insert_query % d_insert)

        return

    f = join(tmp_dir, types[storage]['file'])

    c_f = l_parser.CertmanagerFile(f, timezone=3)
    c_file_type = c_f.file_type
    c_info = c_f.get_info()

    # а так же определить запросы для добавления и удаления данных и упорядочить
    if c_file_type == 'CERT':
        insert_query = certificate_data_insert_query
        c_info = sorted(c_info, key=lambda i: i.subj_key_id)
    else:
        insert_query = crl_data_insert_query
        c_info = sorted(c_info, key=lambda i: i.auth_key_id)

    key_status = 0

    bar = progressbar.ProgressBar(maxval=len(c_info), widgets=[
        'Обработка хранилища %s сервера %s' % (storage, server),
        progressbar.Bar(left=' [', marker='#', right='] '),
        progressbar.SimpleProgress(),
    ]).start()

    for rec in c_info:
        insert_func(rec)
        key_status += 1
        bar.update(key_status)
    bar.finish()
    cn.disconnect()


# ОСНОВНОЙ КОД
if __name__ == '__main__':

    logger = logger_module.logger()

    try:
        # парсим аргументы командной строки
        my_parser = create_parser()
        namespace = my_parser.parse_args()

        if namespace.version:
            show_version()
            exit(0)

        if namespace.server:
            u_server_list.append(namespace.server)
        else:
            u_server_list = d_server_list

        if namespace.file:
            u_storage_list.append(namespace.file)
        elif namespace.number:
            u_storage_list.append(type_by_number[namespace.number])
        else:
            u_storage_list = d_storage_list

        if namespace.remove:
            cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
            cn.connect()
            if namespace.server:
                u_server_list.append(namespace.server)
            else:
                u_server_list = d_server_list

            if namespace.minutes:
                minute = namespace.minutes
            else:
                minute = d_minutes

            for server in u_server_list:
                cn.execute_query(certificate_data_delete_query, minute, server)
                cn.execute_query(crl_data_delete_query, minute, server)

            info = 'Сведения за %s минут удалены' % minute
            print(info)
            logger.info(info)
            cn.disconnect()
            exit(0)

        if namespace.update:
            for server in u_server_list:

                # сброс всех старых записей на active = 0
                cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
                with cn.open():
                    cn.execute_query(certificate_data_drop_active, server)
                    cn.execute_query(crl_data_drop_active, server)

                print('Получение данных сервера %s' % server)
                l_parser.get_info_file(server, out_dir=tmp_dir)
                for storage in u_storage_list:
                    insert_worker(server, storage)

            info = 'Данные обновлены'
            print(info)
            logger.info(info)
            exit(0)

        show_version()
        print('For more information run use --help')

    # если при исполнении будут исключения - кратко выводим на терминал, остальное - в лог
    except Exception as e:
        logger.fatal('Fatal error! Exit', exc_info=True)
        print('Critical error: %s' % e)
        print('More information in log file')
        exit(1)

    exit(0)



