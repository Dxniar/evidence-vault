"""Merge the Windows evidence with the maintained laboratory theory."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"


def main():
    data = json.loads((LABS / "results/lab4-windows.json").read_text(encoding="utf-8-sig"))
    applied = bool(data.get("completed") and data.get("desired_settings_match"))
    title = "# Лабораторная работа № 4\n\n"
    intro = (
        "**Тема:** Реализация политики безопасности в MS Windows.\n\n"
        "**Цель работы:** освоение средств администрирования и аудита.\n\n"
        "**Выполнил:** [ФИО студента]. **Группа:** [группа]. **Проверил:** [ФИО преподавателя].\n\n"
        "Рабочая станция Windows запускает браузер и Docker для Evidence Vault. "
        "Политика входа и журнал Security защищают рабочую станцию; пароль, TOTP, "
        "Google OpenID Connect, роли и журнал приложения защищают доступ к делам. "
        "Это отдельные уровни защиты.\n\n"
        "## Фактический результат выполнения\n\n"
    )
    if applied:
        verified = datetime.fromisoformat(data["verified_utc"].replace("Z", "+00:00"))
        local_verified = verified.astimezone(timezone(timedelta(hours=5)))
        intro += (
            f"Применение проверено {local_verified:%d.%m.%Y в %H:%M:%S} "
            "(Asia/Qyzylorda, UTC+5). "
            "Пять заданных параметров входа применены и прочитаны обратно. "
            "Успех и отказ включены во всех подкатегориях пяти требуемых категорий аудита. "
            "Дополнительно настроен приоритет расширенного аудита. Результат сохранён "
            "в `labs/results/lab4-windows.json`; исходные значения и политика аудита "
            "сохранены отдельно для отката.\n\n"
            "| Параметр | Полученное значение | Проверка |\n|---|---|---|\n"
        )
        for item in data["registry"]:
            intro += f"| `{item['name']}` | {item['value']} | {'Совпало' if item['matches'] else 'Не совпало'} |\n"
        intro += "\n| Категория аудита | Подкатегорий | Успех и отказ |\n|---|---:|---|\n"
        for item in data["audit"]:
            intro += f"| {item['name']} | {len(item['subcategories'])} | {'Включены' if item['success_and_failure'] else 'Не подтверждены'} |\n"
        log = data["security_log"]
        log_enabled = "да" if log["enabled"] else "нет"
        log_mode = "циклический, старые записи замещаются" if log["mode"] == "Circular" else log["mode"]
        intro += (f"\nЖурнал Security включён: {log_enabled}. Путь: `{log['path']}`. "
                  f"Предельный размер: {log['maximum_size_bytes']} байт "
                  f"({log['maximum_size_bytes'] // (1024 * 1024)} МиБ); режим: {log_mode}. "
                  "Свойства журнала прочитаны; его размер и режим не изменялись.\n\n"
                  "### Обнаруженные события Windows\n\n"
                  "Полные XML трёх событий сохранены в `labs/private/windows/security-events.xml`. "
                  "Ниже показаны данные для учебного отчёта; имена, домены и SID скрыты.\n\n")
        events = data["events"]
        event_fields = [{field["name"]: field.get("value") for field in item["data"]}
                        for item in events]
        common_fields = {name: value for name, value in event_fields[0].items()
                         if all(fields.get(name) == value for fields in event_fields)}
        intro += ("### Общие поля обезличенных записей\n\n"
                  f"Идентификаторы событий: {', '.join(str(item['id']) for item in events)}. "
                  f"Поставщик: {events[0]['provider']}; уровень: {events[0]['level']}. "
                  "Одинаковые значения приведены один раз; время, номер записи и "
                  "различающиеся поля приведены отдельно для каждого события.\n\n"
                  "| Поле | Значение во всех трёх записях |\n|---|---|\n")
        for name, value in common_fields.items():
            safe_value = str(value or "—").replace("|", "\\|")
            intro += f"| {name} | {safe_value} |\n"
        intro += ("\n### Отдельные записи журнала\n\n"
                  "| Запись и время UTC | Категория и подкатегория | Отличающиеся поля |\n"
                  "|---|---|---|\n")
        for item, fields in zip(events, event_fields):
            event_guid = str(fields.get("SubcategoryGuid") or "")
            event_category = next((category for category in data["audit"]
                                   if any(sub["guid"].lower() == event_guid.lower()
                                          for sub in category["subcategories"])), None)
            label = "—"
            if event_category:
                subcategory = next(sub for sub in event_category["subcategories"]
                                   if sub["guid"].lower() == event_guid.lower())
                label = f"{event_category['name']}: {subcategory['name']}"
            differing = "; ".join(f"`{name}`: {value}" for name, value in fields.items()
                                  if name not in common_fields).replace("|", "\\|")
            intro += (f"| {item['record_id']}; `{item['time_utc']}` | "
                      f"{label} | {differing or '—'} |\n")
        intro += "\n"
    else:
        intro += (
            "Подготовлены сценарий применения, резервная копия и проверка отката. "
            "Завершённое применение пока не подтверждено: повторный запуск "
            "от имени администратора Windows завершился сообщением «Операция была "
            "отменена пользователем», процесс администратора не стартовал. "
            "Для завершения нужно запустить `labs/windows/Запустить_ЛР4.cmd` "
            "из обычного сеанса пользователя и подтвердить системный запрос. "
            "Этот отчёт не объявляет настройки применёнными.\n\n"
            "Дополнительная проверка обнаружила ошибку прежнего чтения резервной "
            "копии аудита: Windows записала неэкранированные запятые в названиях "
            "двух подкатегорий. Исправленный сценарий читает все 60 подкатегорий "
            "по GUID и числовому значению. Пять проверок чтения файла прошли "
            "в PowerShell 5.1 и 7; это проверка сохранённых файлов и искусственных "
            "примеров, а не подтверждение применения политики Windows.\n\n"
            "В последнем сохранённом снимке отката 58 подкатегорий совпадают с "
            "исходными. Аудит использования прав, затрагивающих и не затрагивающих "
            "конфиденциальные данные, остался включён для успеха и отказа "
            "(исходное значение 0, полученное 3). Полный откат аудита ранее был "
            "объявлен подтверждённым ошибочно; результат проверки исправлен. "
            "Текущее состояние аудита требует чтения с правами администратора. "
            "Шесть параметров реестра повторно прочитаны и совпали с исходными.\n\n"
        )
    intro += (
        "### Ограничение редакции Windows\n\n"
        "На компьютере Windows 11 Home, сборка 26100; `secpol.msc` отсутствует. "
        "Окна уровней и дополнительных правил SRP не были открыты. "
        "Экранные формы этих оснасток из задания остаются невыполненным пунктом "
        "для Windows Pro или другой поддерживаемой редакции. Изображения приложения "
        "не подменяют эти доказательства. Фактический вид следующего экрана входа "
        "также не проверен: рабочий сеанс не завершался.\n\n"
        "## Применение, проверка и откат\n\n"
        "```powershell\n"
        "# Запуск из обычного сеанса пользователя:\n"
        "labs\\windows\\Запустить_ЛР4.cmd\n"
        "# Только чтение, из PowerShell администратора:\n"
        "powershell -NoProfile -File labs/windows/Set-Lab4Policy.ps1 -Mode Inspect\n"
        "# Возврат исходных значений на этом же компьютере:\n"
        "powershell -NoProfile -File labs/windows/Set-Lab4Policy.ps1 -Mode Restore\n"
        "```\n\n"
        "Сценарий сохраняет значения реестра с типами и контрольную сумму резервной "
        "копии аудита. Он проверяет успех каждой команды, читает полученные параметры "
        "и при ошибке пытается восстановить исходное состояние. При отказе восстановления "
        "CSV используются сохранённые GUID подкатегорий с последующей сверкой. "
        "Перезагрузка, очистка Security, изменение паролей и запрет запуска программ "
        "не выполняются.\n\n"
    )
    theory = (LABS / "content/lab4_theory.md").read_text(encoding="utf-8")
    theory = theory.split("\n", 1)[1]
    start = theory.find("## Что наблюдалось и что нужно подтвердить")
    end = theory.find("## Вывод", start)
    if start >= 0 and end > start:
        theory = theory[:start] + theory[end:]
    (LABS / "content/lab4.md").write_text(title + intro + theory, encoding="utf-8")
    print(json.dumps({"windows_configuration_verified": applied, "report_source_written": True}))


if __name__ == "__main__":
    main()
