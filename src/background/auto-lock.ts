import { readVaultTimeoutMinutes } from "../shared/settings";

const ALARM = "leanvault-auto-lock";

export async function touchAutoLock(unlocked: boolean): Promise<void> {
  const minutes = unlocked ? await readVaultTimeoutMinutes() : 0;
  if (minutes <= 0) {
    await chrome.alarms.clear(ALARM);
    return;
  }
  chrome.alarms.create(ALARM, { delayInMinutes: minutes });
}

export function isAutoLockAlarm(alarm: chrome.alarms.Alarm): boolean {
  return alarm.name === ALARM;
}
