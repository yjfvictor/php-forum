/**
 * @file utils.ts
 * @brief Utility functions for the forum frontend
 * @details Contains helper functions for date formatting and API communication
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */

/**
 * @brief Pad string with leading characters (ES5 compatible)
 * @param str String to pad
 * @param length Target length
 * @param padChar Character to pad with
 * @return string Padded string
 */
function padStart(str: string, length: number, padChar: string): string {
    const strValue = String(str);
    if (strValue.length >= length) {
        return strValue;
    }
    let pad = '';
    for (let i = 0; i < length - strValue.length; i++) {
        pad += padChar;
    }
    return pad + strValue;
}

/**
 * @brief Get timezone name (ES5 compatible)
 * @param date Date object
 * @return string Timezone name or abbreviation
 */
function getTimezoneName(date: Date): string {
    // Try to get timezone name using toTimeString
    const timeString = date.toTimeString();
    // Extract timezone from string like "12:00:00 GMT-0800 (PST)"
    const match = timeString.match(/\(([^)]+)\)/);
    if (match && match[1]) {
        return match[1];
    }
    // Fallback: try to get from toString
    const toString = date.toString();
    const match2 = toString.match(/\(([^)]+)\)/);
    if (match2 && match2[1]) {
        return match2[1];
    }
    // Last resort: use offset abbreviation
    const offset = -date.getTimezoneOffset();
    const offsetHours = Math.floor(Math.abs(offset) / 60);
    const offsetMinutes = Math.abs(offset) % 60;
    const offsetSign = offset >= 0 ? '+' : '-';
    return 'GMT' + offsetSign + padStart(String(offsetHours), 2, '0') + padStart(String(offsetMinutes), 2, '0');
}

/**
 * @brief Convert Unix timestamp to "YYYY-MM-DD HH:mm:ss TIMEZONE" format in local timezone
 * @param timestamp Unix timestamp in seconds
 * @return string Formatted date string in "YYYY-MM-DD HH:mm:ss TIMEZONE" format
 */
export function formatDate(timestamp: number): string {
    const date = new Date(timestamp * 1000);
    const year = date.getFullYear();
    const month = padStart(String(date.getMonth() + 1), 2, '0');
    const day = padStart(String(date.getDate()), 2, '0');
    const hours = padStart(String(date.getHours()), 2, '0');
    const minutes = padStart(String(date.getMinutes()), 2, '0');
    const seconds = padStart(String(date.getSeconds()), 2, '0');
    
    // Get timezone name
    const timezone = getTimezoneName(date);
    
    return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds + ' ' + timezone;
}

/**
 * @brief Show Bootstrap alert
 * @param message Alert message
 * @param type Alert type (success, danger, warning, info)
 * @param container Container element to append alert to
 */
export function showAlert(message: string, type: string, container: HTMLElement): void {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

/**
 * @brief Show Bootstrap modal for confirmation
 * @param message Confirmation message
 * @param onConfirm Callback function when confirmed
 * @param onCancel Optional callback function when cancelled
 */
export function showConfirmModal(message: string, onConfirm: () => void, onCancel?: () => void): void {
    // Remove existing modal if any
    const existingModal = document.getElementById('confirmModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    const modalDiv = document.createElement('div');
    modalDiv.id = 'confirmModal';
    modalDiv.className = 'modal fade';
    modalDiv.setAttribute('tabindex', '-1');
    modalDiv.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Confirm</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>${message}</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="confirmBtn">Confirm</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modalDiv);
    
    const modal = new (window as any).bootstrap.Modal(modalDiv);
    modal.show();
    
    const confirmBtn = document.getElementById('confirmBtn');
    if (confirmBtn) {
        confirmBtn.onclick = () => {
            modal.hide();
            onConfirm();
            modalDiv.remove();
        };
    }
    
    modalDiv.addEventListener('hidden.bs.modal', () => {
        if (onCancel) {
            onCancel();
        }
        modalDiv.remove();
    });
}

