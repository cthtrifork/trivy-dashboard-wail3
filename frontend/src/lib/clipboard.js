import { ScanService } from "../store.js";

// Every copy in the app goes through here. The native clipboard comes first;
// server mode has none (ScanService.CopyText errors there), so use the browser's.
export async function copyText(text) {
  try {
    await ScanService.CopyText(text);
  } catch {
    await webCopy(text);
  }
}

async function webCopy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;opacity:0";
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}
