# xenoeye
Легкий коллектор Netflow

[![Build Status](https://app.travis-ci.com/vmxdev/xenoeye.svg?branch=master)](https://app.travis-ci.com/vmxdev/xenoeye)

С помощью этого коллектора и [Netflow](https://ru.wikipedia.org/wiki/Netflow) вы сможете

  * Видеть потребление и испускание трафика IP-сетями, отдельными IP-адресами или сервисами
  * Мониторить сетевой трафик и быстро реагировать на всплески
  * Наблюдать за характером сетевого трафика, распределением пакетов по разным Netflow полям


## Ключевые особенности

Пожалуйста, прочитайте внимательно: некоторые пункты могут быть для вас неприемлемыми

  * Проект находится в бета-состоянии. Коллектор работает у нас, но мы не можем дать никаких гарантий что он будет работать у вас
  * Это не готовое бизнес-решение, а набор из программы-коллектора и вспомогательных скриптов. Тем не менее, с помощью коллектора вы cможете генерировать почти произвольные отчеты о сетевом трафике, строить графики разными способами, смотреть на "живые" данные в Графане и запускать пользовательские скрипты, когда скорость сетевого трафика превышает лимиты
  * Мы используем коллектор для мониторинга своих сетей. У нас используется Netflow v9 и IPFIX. Коллектор поддерживает только эти версии
  * В отличие от многих современных коллекторов мы *не используем* Apache Kafka, Elastic стек или что-то подобное. Основные рассчеты происходят внутри самого коллектора
  * В документации есть примеры построения простых отчетов, но для построения более сложных нужно хотя бы базовое знание SQL
  * Коллектор обрабатывает данные двумя способами: агрегирует их во временных окнах фиксированного размера (для получения отчетов и графиков), и использует скользящие средние для быстрой реакции на всплески
  * Оба способа могут использоваться как по отдельности, так и совместно. Например, если с помощью скользящего среднего обнарушилось превышение порога, кроме запуска пользовательского скрипта можно сразу же включить сбор расширенной статистики
  * Коллектор не очень требователен к ресурсам. Он вполне может обрабатывать данные и строить отчеты даже на Orange Pi (аналог Raspberry Pi) с 4Г памяти
  * Ядро коллектора написано на Си
  * Коллектор тестировался только под 64-битным Linux (x64 и AArch64)
  * Мы используем PostgreSQL в качестве хранилища для временных рядов. Туда экспортируются агрегированные по выбранным Netflow-полям данные. Агрегация происходит внутри коллектора
  * Из коробки поддерживается не очень большой набор Netflow-полей. Но вы можете добавить почти любое поле. Сейчас поддерживаются поля с типами "целое" (разного размера) и "адрес" (IPv4 и IPv6)
  * У проекта очень либеральная лицензия. У нас нет никаких планов делать коммерческие или частично коммерческие версии. Это значит, что мы не можем дать никаких прогнозов относительно будущего проекта. Но, с другой стороны
  * В коллекторе нет никаких скрытых или искусственных ограничений


## Производительность

В мире Netflow-коллекторов нет стандартной методики тестирования производительности. Более того, многие производители коллекторов вообще не пишут о производительности своих продуктов.
То есть мы не можем назвать свой коллектор "быстрым" или хотя бы "высокопроизводительным".

Чтобы увидеть какие-то данные о производительности, мы сделали несколько тестов: записали в pcap-файлы реальный трафик разных роутеров и проиграли их на лупбек-интерфейсе с помощью tcpreplay на разной скорости

Очень грубо можно ориентироваться на такие цифры:
В отладочном режиме, когда в файл печатается содержимое каждого флова у нас получилось около 100K flow в секунду на одном CPU
В немного более приближенном к продакшен-режиму, с двумя объектами мониторинга, двумя скользящими окнами - около 700K fps на одном CPU.

Эти цифры лучше читать с пессимистичным настроением:
  1. если вы нагрузите коллектор многими объектами мониторинга с кучей отчетов и отладочной печатью, он может захлебнуться на 100K fps/CPU и меньше
  2. скорее всего 700K fps и больше на одном CPU обсчитать не получится

Про масштабирование на несколько ядер написано ниже в документации

## Документация

Пошаговая инструкция по установке и настойке
  Сборка и установка
  Проверяем получение Netflow
  Роутеры и распределение нагрузки по нескольким CPU
  Частота семплирования
  Объекты мониторинга
  Настраиваем окна фиксированного размера
  Экспорт в СУБД
  Простые отчеты по IP-адресам
  Определяем спам-ботов и ssh-сканеры
  Строим графики с помощью gnuplot
  Графики с помощью Python Matplotlyb
  Визуализация трафика в Графане
  Скользящие средние
  Настройка и установка порогов
  Скрипты и их параметры
  Расширенная статистика
  Оповещение об аномалиях с помощью Telegram-робота

Полное описание конфигурационных файлов
  xenoeye.conf
  devices.conf
  mo.conf

Внутреннее устройство
  Общие сведения
  Как добавить новое Netflow-поле
  Объекты мониторинга и фильтры
  Фиксированные временные окна
  Скользящие средние

## Будущее

Пока мы не планируем добавлять новые фичи. Допиливаем внутреннее устройство, ищем и пытаемся исправить баги

Возможно, добавим Netflow v5
