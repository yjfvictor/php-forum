/**
 * @file utils.ts
 * @brief Utility functions for the forum frontend
 * @details Contains helper functions for date formatting and API communication
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */
define(["require", "exports"], function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.showConfirmModal = exports.showAlert = exports.formatDate = void 0;
    /**
     * @brief Pad string with leading characters (ES5 compatible)
     * @param str String to pad
     * @param length Target length
     * @param padChar Character to pad with
     * @return string Padded string
     */
    function padStart(str, length, padChar) {
        var strValue = String(str);
        if (strValue.length >= length) {
            return strValue;
        }
        var pad = '';
        for (var i = 0; i < length - strValue.length; i++) {
            pad += padChar;
        }
        return pad + strValue;
    }
    /**
     * @brief Get timezone name (ES5 compatible)
     * @param date Date object
     * @return string Timezone name or abbreviation
     */
    function getTimezoneName(date) {
        // Try to get timezone name using toTimeString
        var timeString = date.toTimeString();
        // Extract timezone from string like "12:00:00 GMT-0800 (PST)"
        var match = timeString.match(/\(([^)]+)\)/);
        if (match && match[1]) {
            return match[1];
        }
        // Fallback: try to get from toString
        var toString = date.toString();
        var match2 = toString.match(/\(([^)]+)\)/);
        if (match2 && match2[1]) {
            return match2[1];
        }
        // Last resort: use offset abbreviation
        var offset = -date.getTimezoneOffset();
        var offsetHours = Math.floor(Math.abs(offset) / 60);
        var offsetMinutes = Math.abs(offset) % 60;
        var offsetSign = offset >= 0 ? '+' : '-';
        return 'GMT' + offsetSign + padStart(String(offsetHours), 2, '0') + padStart(String(offsetMinutes), 2, '0');
    }
    /**
     * @brief Convert Unix timestamp to "YYYY-MM-DD HH:mm:ss TIMEZONE" format in local timezone
     * @param timestamp Unix timestamp in seconds
     * @return string Formatted date string in "YYYY-MM-DD HH:mm:ss TIMEZONE" format
     */
    function formatDate(timestamp) {
        var date = new Date(timestamp * 1000);
        var year = date.getFullYear();
        var month = padStart(String(date.getMonth() + 1), 2, '0');
        var day = padStart(String(date.getDate()), 2, '0');
        var hours = padStart(String(date.getHours()), 2, '0');
        var minutes = padStart(String(date.getMinutes()), 2, '0');
        var seconds = padStart(String(date.getSeconds()), 2, '0');
        // Get timezone name
        var timezone = getTimezoneName(date);
        return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds + ' ' + timezone;
    }
    exports.formatDate = formatDate;
    /**
     * @brief Show Bootstrap alert
     * @param message Alert message
     * @param type Alert type (success, danger, warning, info)
     * @param container Container element to append alert to
     */
    function showAlert(message, type, container) {
        var alertDiv = document.createElement('div');
        alertDiv.className = "alert alert-".concat(type, " alert-dismissible fade show");
        alertDiv.setAttribute('role', 'alert');
        alertDiv.innerHTML = "\n        ".concat(message, "\n        <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\" aria-label=\"Close\"></button>\n    ");
        container.insertBefore(alertDiv, container.firstChild);
        // Auto-dismiss after 5 seconds
        setTimeout(function () {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
    exports.showAlert = showAlert;
    /**
     * @brief Show Bootstrap modal for confirmation
     * @param message Confirmation message
     * @param onConfirm Callback function when confirmed
     * @param onCancel Optional callback function when cancelled
     */
    function showConfirmModal(message, onConfirm, onCancel) {
        // Remove existing modal if any
        var existingModal = document.getElementById('confirmModal');
        if (existingModal) {
            existingModal.remove();
        }
        var modalDiv = document.createElement('div');
        modalDiv.id = 'confirmModal';
        modalDiv.className = 'modal fade';
        modalDiv.setAttribute('tabindex', '-1');
        modalDiv.innerHTML = "\n        <div class=\"modal-dialog\">\n            <div class=\"modal-content\">\n                <div class=\"modal-header\">\n                    <h5 class=\"modal-title\">Confirm</h5>\n                    <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"modal\" aria-label=\"Close\"></button>\n                </div>\n                <div class=\"modal-body\">\n                    <p>".concat(message, "</p>\n                </div>\n                <div class=\"modal-footer\">\n                    <button type=\"button\" class=\"btn btn-secondary\" data-bs-dismiss=\"modal\">Cancel</button>\n                    <button type=\"button\" class=\"btn btn-primary\" id=\"confirmBtn\">Confirm</button>\n                </div>\n            </div>\n        </div>\n    ");
        document.body.appendChild(modalDiv);
        var modal = new window.bootstrap.Modal(modalDiv);
        modal.show();
        var confirmBtn = document.getElementById('confirmBtn');
        if (confirmBtn) {
            confirmBtn.onclick = function () {
                modal.hide();
                onConfirm();
                modalDiv.remove();
            };
        }
        modalDiv.addEventListener('hidden.bs.modal', function () {
            if (onCancel) {
                onCancel();
            }
            modalDiv.remove();
        });
    }
    exports.showConfirmModal = showConfirmModal;
});
