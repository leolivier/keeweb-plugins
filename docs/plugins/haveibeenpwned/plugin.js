/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const Logger = require('util/logger');
/**
 * local logger
 * @type {Logger}
 */
const hLogger = new Logger('HaveIBeenPwned');
/** change log level here. Should be changed to Debug/Warn when issue #893 fixed on keeweb */
const HLoggerDebug = Logger.Level.All;
const HLoggerRegular = Logger.Level.Info;
hLogger.setLevel(HLoggerRegular);

/**
 * Cache time to live
 * Set to 14 days (in milliseconds)
 * @type {number}
 */
const CacheTTL = 1000 * 3600 * 24 * 14;

/** Strings that should be localized */
const HIBPLocale = {
    hibpCheckPwnedPwd: 'Should I check passwords against HaveIBeenPwned list?',
    hibpCheckPwnedName: 'Should I check user name against HaveIBeenPwned list?',
    hibpCheckLevelNone: 'No thanks, don\'t check',
    hibpCheckLevelAlert: 'Yes and alert me if pwned',
    hibpCheckLevelAskMe: 'Yes and ask me if pwned',
    hibpCheckOnList: 'Show pawned entries on list',
    hibpPwdWarning: `WARNING! This password was used by {} pawned accounts referenced on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a>!`,
    hibpNameWarning: 'WARNING! The account named "{name}" has been pawned in the following breaches<br/><ul>{breaches}</ul><p>Please check on <a href=\'https://haveibeenpwned.com\'>https://haveibeenpwned.com</a></p>',
    hibpChangePwd: 'Do you want to keep this new password?',
    hibpChangeName: 'Do you want to keep this new user name?',
    hibpApiError: 'HaveIBeenPwned API error'
};

/** What chcking level to use
 * None: no checking
 * Alert: Draw an alert near the pawned item
 * AskMe: Interactively ask me to revert to the previous value if pawned
 */
const HIBPCheckLevel = {
    None: 'none',
    Alert: 'alert',
    AskMe: 'askme'
};

/** Required modules */
const DetailsView = require('views/details/details-view');
const ListView = require('views/list-view');
const AppModel = require('models/app-model');
const InputFx = require('util/input-fx');
const Kdbxweb = require('kdbxweb');
const _ = require('_');
const Tip = require('util/tip');
const Alerts = require('comp/alerts');
const StorageBase = require('storage/storage-base');
const IoCache = require('storage/io-cache');
const Launcher = require('comp/launcher');

/** Keeps track of 4 replaced methods */
const detailsViewFieldChanged = DetailsView.prototype.fieldChanged;
const detailsViewAddFieldViews = DetailsView.prototype.addFieldViews;
const listViewRender = ListView.prototype.render;
const appModelGetEntriesByFilter = AppModel.prototype.getEntriesByFilter;

/**
 * Storage cache based on IoCache.
 * Inspired from storage-cache.js with a specific config
 * TODO: test this cache in Desktop app
 */
class StorageCache extends StorageBase {
    constructor() {
        super();
        this.name = 'cache';
        this.enabled = IoCache.enabled;
        this.system = true;
        this.init(); // storage base
        this.io = new IoCache({
            cacheName: 'HIBPCache',
            logger: hLogger
        });
    };

    save(id, data, callback) {
        if (Launcher) data = Kdbxweb.ByteUtils.stringToBytes(JSON.stringify(data));
        this.io.save(id, data, callback);
    };
    load(id, callback) {
        this.io.load(id, Launcher ? (err, res) => {
            if (err) callback(err);
            else {
                const str = Kdbxweb.ByteUtils.bytesToString(res);
                // hLogger.debug('cache.load', str);
                const data = JSON.parse(str);
                callback(err, data);
            }
        } : callback);
    };
    remove(id, callback) {
        this.io.remove(id, callback);
    }
};

const HIBPUtils = {
    /**
     * xor between two objects
     */
    xor: (any1, any2) => {
        // !any1 ==> boolean, same for !any2, xor = true if they're different
        return (!any1 !== !any2);
    },
    /**
     * Prints a stack trace in debug mode
     */
    stackTrace: () => {
        const err = new Error();
        hLogger.debug(err.stack);
    },
    /**
     * XML HTTP Request with Promises,
     * @param {object} config the XML HTTP Request configuration. Same as in StorageBase.
     * @returns {Promise}
     */
    xhrpromise: (config) => {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            if (config.responseType) {
                xhr.responseType = config.responseType;
            }
            const statuses = config.statuses || [200];
            xhr.open(config.method || 'GET', config.url);
            if (config.headers) {
                _.forEach(config.headers, (value, key) => {
                    xhr.setRequestHeader(key, value);
                });
            };
            xhr.addEventListener('load', () => {
                if (statuses.indexOf(xhr.status) >= 0) {
                    resolve({ status: xhr.status, data: xhr.response });
                } else {
                    hLogger.error(HIBPLocale.hibpApiError, '>GET', xhr.status, xhr.statusText);
                    reject(xhr.statusText);
                }
            });
            xhr.addEventListener('error', () => {
                // status = 503 means cloudflare started the DDOS protection, must be handled
                if (xhr.status === 503) {
                    resolve({ status: 503, data: null });
                } else {
                    const err = xhr.response && xhr.response.error || new Error('Network error');
                    hLogger.error(HIBPLocale.hibpApiError, 'GET>', xhr.status, err);
                    reject(xhr.statusText);
                }
            });
            xhr.send(config.data);
        });
    },
    /**
     * Applies a digest algorithm on input string
     * @param {algo} algorithm to be applied (e.g. 'SHA-1' 'SHA-2456'
     * @returns {string} the "digested" hex string
     */
    digest: (algo, str) => {
        const buffer = Kdbxweb.ByteUtils.stringToBytes(str);
        const subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        return subtle.digest(algo, buffer).then(buffer => {
            // transforms the buffer into an hex string
            const hexCodes = [];
            const view = new DataView(buffer);
            for (let i = 0; i < view.byteLength; i += 4) {
                // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
                const value = view.getUint32(i);
                // toString(16) will give the hex representation of the number without padding
                const stringValue = value.toString(16);
                // We use concatenation and slice for padding
                const padding = '00000000';
                const paddedValue = (padding + stringValue).slice(-padding.length);
                hexCodes.push(paddedValue);
            }
            // Join all the hex strings into one
            return hexCodes.join('');
        });
    }
};

/**
 * This is were most HaveIBeenPwned stuff lies.
 */
class HIBP {
    constructor() {
        // the 3 options with their default values
        this.checkPwnedPwd = HIBPCheckLevel.Alert;
        this.checkPwnedName = HIBPCheckLevel.Alert;
        this.checkPwnedList = false;
        // cache variables
        this._pwnedNamesCache = new Map();
        this._pwnedPwdsCache = new Map();
        // cache manager
        this._storage = new StorageCache();
        this._loadCache('_pwnedNamesCache');
        this._loadCache('_pwnedPwdsCache');
        // names and pwds waiting to be checked by the scanenr
        this._waitingNames = [];
        this._waitingPwds = [];
        // the ApplicationModel object
        this._appModel = null;
        // start the scanner
        this._initScanner();
        // check if the scan had been stopped and stored in cache in a previous session
        this._storage.load('stopCheckingNamesUntil', (err, res) => {
            if (err) {
                hLogger.info('can\'t load cache stopCheckingNamesUntil: ', err);
            } else {
                this.stopCheckingNames = res;
                if (this.stopCheckingNames && this.stopCheckingNames > Date.now()) this._stopScanner(this.stopCheckingNames - Date.now());
                else {
                    this.stopCheckingNames = false;
                    this._storage.remove('stopCheckingNamesUntil');
                }
            }
        });
    }
    /**
     * starts a scanner for checking names & pwds asynchronously
     * Do some throttling on names as HIBP does not allow more than one call every 1500 millisecs
     */
    _initScanner() {
        this.stopCheckingNames = false;
        // millisecs betwwen 2 calls
        const throttle = 2000;
        this.interval = setInterval(() => {
            this.checkNextWaitingElems();
        }, throttle);
    }
    /**
     * Stop the scanner for a given duration
     * Used when ddos attack detected on CloudFlare, see checkNamePwned method
     * @param {number} duration
     */
    _stopScanner(duration) {
        // date when the scan will restart
        this.stopCheckingNames = Date.now() + duration;
        clearInterval(this.interval);
        // store in cache so that we can find it even if the session is interrupted
        this._storage.save('stopCheckingNamesUntil', this.stopCheckingNames);
        // restart the scanner after duration
        setTimeout(() => {
            this._initScanner();
        }, duration);
    }
    /**
     * Add css stuff + tip on fields to show an alert on pawned fields
     * @param {Element} el the HTML element of the field
     * @param {string} msg the message to print in the tip
     */
    _alert(el, msg) {
        hLogger.info(msg);
        el.focus();
        el.addClass('input--error');
        el.find('.details__field-value').addClass('hibp-pwned');
        Tip.createTip(el, { title: msg, placement: 'bottom' });
        InputFx.shake(el);
    };
    /**
     * Reset css stuff and tip on fields to remove alerts on pawned fields
     * @param {Element} el the HTML element of the field
     * @param {string} msg the message to print in the console
     */
    _passed(el, msg) {
        hLogger.info(msg);
        el.removeClass('input--error');
        el.find('.details__field-value').removeClass('hibp-pwned');
        const tip = el._tip;
        if (tip) {
            tip.hide();
            tip.title = null;
        }
    }
    /**
     * Store the desired cache in local storage
     * @param {string} cacheVarName the name of the cache variable ('_pwnedNamesCache' or '_pwnedPwdsCache')
     */
    _storeCache(cacheVarName) {
        const cache = [];
        this[cacheVarName].forEach((value, key) => {
            cache.push({ key: key, value: value });
        });
        // hLogger.debug('storing cache', cacheVarName, cache);
        this._storage.save(cacheVarName, cache, (err) => {
            err && hLogger.error('can\'t store cache', cacheVarName, cache, err);
        });
    }
    /**
     * Load desired cache from local storage
     * Values older than CacheTTL are discarded
     * @param {string} cacheVarName the name of the cache variable ('_pwnedNamesCache' or '_pwnedPwdsCache')
     */
    _loadCache(cacheVarName) {
        this._storage.load(cacheVarName, (err, res) => {
            if (err) {
                hLogger.warn('can\'t load cache', cacheVarName, err);
            } else {
                // hLogger.debug('load cache', res);
                // check each element to remove too old ones
                Array.isArray(res) && res.forEach(entry => {
                    const diff = Date.now() - entry.value.date; // cache age in millisec
                    if (diff < CacheTTL) {
                        this[cacheVarName].set(entry.key, entry.value);
                    } else {
                        hLogger.info('cache too old', cacheVarName, entry.key);
                        this[cacheVarName].delete(entry.key); // You never know...
                    }
                });
                // hLogger.debug('_loadCache', this[cacheVarName]);
            }
        });
    }
    /**
     * true if cached element exist and is not too old
     * @param {string} cachedElem the cache element to check
     * @returns {boolean} true if the elem is in the cache and is not too old, else false
     */
    _isInCache(cacheName, elemId) {
        const cachedElem = this[cacheName].get(elemId);
        if (cachedElem) {
            if ((Date.now() - cachedElem.date) < CacheTTL) return true;
            else {
                this[cachedElem].remove(elemId);
                return false;
            }
        } else return false;
    }
    /**
     * get a name or a password breach from the cache
     * @param {string} cacheName the name of the cache variable ('_pwnedNamesCache' or '_pwnedPwdsCache')
     * @param {string} elemId the name or the pwd to find from the cache
     * @returns {string or number} the value from the cache (the value can be null, you *must* call _isInCache before calling _getCache)
     */
    _getCache(cacheName, elemId) {
        const cachedElem = this[cacheName].get(elemId);
        if (!cachedElem) throw new Error(`elem {elemId} not found in cache {cacheName}`);
        return cachedElem.val;
    }
    _setCache(cacheName, elemId, val) {
        this[cacheName].set(elemId, { date: Date.now(), val: val });
    }
    /**
     * Computes and returns the SHA1 hash of a string
     * @param {string} str the input string
     * @returns {string} the SHA-1 hex string of the input string
     */
    sha1(str) {
        return HIBPUtils.digest('SHA-1', str);
    };
    /**
     * Computes and returns the SHA256 hash of a string
     * @param {string} str the input string
     * @returns {string} the SHA-256 hex string of the input string
     */
    sha256(str) {
        return HIBPUtils.digest('SHA-256', str);
    };
    /**
     * Checks if the input name is pawned in breaches on haveibeenpwned.
     * Uses a cache to avoid calling hibp again and again with the same values
     * @param {string} name the name to check
     * @returns {Promise} a promise resolving to an html string containing a list of breaches names if pwned, or null if either being checked or not breached
     */
    checkNamePwned (uname) {
        hLogger.debug('checking user name', uname);
        const name = encodeURIComponent(uname);
        if (this._isInCache('_pwnedNamesCache', name)) {
            hLogger.debug('user name found in cache', name);
            return Promise.resolve(this._getCache('_pwnedNamesCache', name));
        } else {
            if (this.stopCheckingNames) return Promise.resolve(null); // do nothing if flag set
            hLogger.debug('USER NAME NOT FOUND in cache', name); // , 'cache=', this._pwnedNamesCache);
            // store the name in cache with a null value so that we don't ask multiple times the same name
            this._setCache('_pwnedNamesCache', name, null);
            const url = `https://haveibeenpwned.com/api/v2/breachedaccount/${name}?truncateResponse=true`;
            // hLogger.debug('url', url);
            return HIBPUtils.xhrpromise({
                url: url,
                method: 'GET',
                responseType: 'json',
                headers: null,
                data: null,
                // 503 is an error but treated in xhrpromise as a resolve case
                statuses: [200, 404, 429]
            }).then(res => {
                hLogger.debug('return from name pwned', res);
                switch (res.status) {
                    case 200:
                        let breaches = '';
                        if (res.data && res.data.length > 0) {
                            // hLogger.debug('found breaches', data);
                            res.data.forEach(breach => { breaches += '<li>' + _.escape(breach.Name) + '</li>'; });
                        }
                        this._setCache('_pwnedNamesCache', name, breaches);
                        if (breaches) hLogger.info(`name ${name} pwned in ${breaches}`);
                        this._storeCache('_pwnedNamesCache');
                        return breaches;
                    case 404:
                        this._setCache('_pwnedNamesCache', name, null);
                        this._storeCache('_pwnedNamesCache');
                        return null;
                    case 429: // Throttling in HIBP
                        hLogger.warn('Warning, too many request on HIBP!');
                        // put back in the waiting list but with no item: at least, it'll be in the cache next time...
                        this._waitingNames.unshift({ name: name, items: [] });
                        break;
                    case 503: // Cloudflare DDOS protection
                        // stop checking names for 24 hours + 1mn
                        hLogger.warn('We did too many requests on haveIBeenPwned.');
                        hLogger.debug('Cloudflare DDOS attack protection is triggered,');
                        hLogger.warn('Stopping requests for 24 hours...');
                        const h24 = (24 * 60 + 1) * 60 * 1000;
                        this._stopScanner(h24);
                }
            }).catch(error => {
                hLogger.error('checkNamePwned: check pwned name error', error.message);
                // reset cache to unknown
                this._pwnedNamesCache.delete(name);
            });
        }
    };
    /**
     * Checks if the input password (hashed in sha-1) is pawned in breaches on haveibeenpwned.
     * Uses a cache to avoid calling hibp again and again with the same values
     * @param { string } pwd the sha1 hashed password to check
     * @returns { Promise } a promise resolving to the number of pwnages if pwned or null
     */
    checkPwdPwned (passwordHash) {
        passwordHash = passwordHash.toUpperCase();
        hLogger.debug('checking pwd (hashed)', passwordHash);
        const prefix = passwordHash.substring(0, 5);
        if (this._isInCache('_pwnedPwdsCache', passwordHash)) {
            const val = this._getCache('_pwnedPwdsCache', passwordHash);
            hLogger.debug('found pwd in cache', passwordHash, val);
            return Promise.resolve(val);
        } else {
            hLogger.debug('PWD NOT FOUND in cache', passwordHash);
            // store the pwd in cache with a null value so that we don't ask multiple times the same pwd
            this._setCache('_pwnedPwdsCache', passwordHash, null);
            return HIBPUtils.xhrpromise({
                url: `https://api.pwnedpasswords.com/range/${prefix}`,
                method: 'GET',
                responseType: 'text',
                headers: null,
                data: null,
                statuses: [200, 404]
            }).then(res => {
                let nb = null;
                if (res.status === 200) {
                    // hLogger.debug('found breaches', data);
                    res.data.split('\r\n').some(line => {
                        const h = line.split(':');
                        const suffix = h[0];
                        if (prefix + suffix === passwordHash) {
                            nb = _.escape(h[1]);
                            hLogger.info(`password ${passwordHash} pawned ${nb} times`);
                            return true;
                        }
                    });
                }
                this._setCache('_pwnedPwdsCache', passwordHash, nb);
                this._storeCache('_pwnedPwdsCache');
                return nb;
            }).catch(error => {
                hLogger.error('check pwned password error', error.message);
                // reset cache
                this._pwnedPwdsCache.delete(passwordHash);
            });
        }
    };
    /**
     * filter passwords needing to be checked
     * @param {string} pwd the password to check
     * @returns {boolean} true if the pwd can be checked
     */
    elligiblePwd (pwd) {
        return (pwd && pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:'));
    }
    /**
     * Change the password field to display an alert or reset it depending on npwned value
     * @param {View} dview the details view
     * @param {number} npwned the number of times the password has been pawned (or null or 0 if none)
     * @param {string} warning the warning to display
     * @param {...} args the arguments to be passed to the original 'fieldChanged' function
     */
    _alertPwdPwned (dview, npwned, warning, args) {
        if (npwned) { // pwned
            // record pawnage in the model to be able to show it in list view
            dview.model.pwdPwned = npwned;
            // calls original function
            detailsViewFieldChanged.apply(dview, args);
            // sets the alert
            this._alert(dview.passEditView.$el, warning);
        } else { // not pwned
            // reset css and tip
            this._passed(dview.passEditView.$el, 'check pwned password passed...');
            // reset pawnage in the model
            dview.model.pwdPwned = null;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
        }
    };
    /**
     * filter names needing to be checked
     * @param {string} name the name to check
     * @returns {boolean} true if the name can be checked
     */
    elligibleName(name) {
        return (name && name.replace(/\s/, '') !== '');
    }
    /**
     * Change the name field to display an _alert or reset it depending on breaches value
     * @param {View} dview the details view
     * @param {string} breaches the breaches in which the name has been pawned (or null or '' if none)
     * @param {string} warning the warning to display
     * @param {...} args the arguments to be _passed to the original 'fieldChanged' function
     */
    _alertNamePwned (dview, breaches, warning, args) {
        if (breaches) { // pwned
            // remember breaches in the model to be able to show it in list view
            dview.model.namePwned = breaches;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
            // adds an alert
            this._alert(dview.userEditView.$el, warning);
        } else { // not pwned
            // reset alert
            this._passed(dview.userEditView.$el, 'check pwned user name _passed...');
            // reset the model
            dview.model.namePwned = null;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
        }
    };
    /**
     * Looks up the password on HaveIBeenPwned and handle the results
     * If the password is pawned, depending on the check level, puts some icon warning, or asks to revert to the previous one
     * @param {DetailedView} dview the detailed view containing the password
     * @param {string} pwd the pwd to check
     */
    handlePasswordChange(dview, pwd, args) {
        pwd = pwd ? pwd.getText() : null;
        if (hibp.elligiblePwd(pwd)) {
            // hLogger.debug('pwd:>>>', pwd, '<<<');
            this.sha1(pwd)
                .then(hpwd => {
                    return this.checkPwdPwned(hpwd);
                })
                .then(npwned => {
                    const warning = HIBPLocale.hibpPwdWarning.replace('{}', npwned);
                    if (npwned) { // pawned
                        if (this.checkPwnedPwd === HIBPCheckLevel.AskMe) {
                            // ask before taking the field change into account
                            Alerts.yesno({
                                header: HIBPLocale.hibpChangePwd,
                                body: warning,
                                icon: 'exclamation-triangle',
                                success: () => { // keep password, just set an alert
                                    this._alertPwdPwned(dview, npwned, warning, args);
                                },
                                cancel: () => { // reset password by not registering change
                                    hLogger.info('keeping old passwd');
                                }
                            });
                        } else { // check level = alert, keep pwd, set an alert
                            this._alertPwdPwned(dview, npwned, warning, args);
                        }
                    } else { // not pawned
                        this._alertPwdPwned(dview, null, null, args);
                    }
                }).catch(error => {
                    hLogger.error('check pwned password error', error.message);
                });
        } else {
            this._alertPwdPwned(dview, null, null, args);
        }
    }
    /**
     * Looks up the user name on HaveIBeenPwned and handle the results
     * If the name is pawned, depending on the check level, puts some icon warning, or asks to revert to the previous one
     * @param {DetailedView} dview the detailed view containing the user name
     * @param {string} name the user name to check
     */
    handleNameChange(dview, name, args) {
        if (this.elligibleName(name)) {
            this.checkNamePwned(name)
                .then(breaches => {
                    if (breaches) { // pawned
                        name = _.escape(name); // breaches already escaped
                        const warning = HIBPLocale.hibpNameWarning.replace('{name}', name).replace('{breaches}', breaches);
                        if (this.checkPwnedName === HIBPCheckLevel.AskMe) {
                            // ask before taking the field change into account
                            Alerts.yesno({
                                header: HIBPLocale.hibpChangeName,
                                body: warning,
                                icon: 'exclamation-triangle',
                                success: () => { // keep name, but set an alert
                                    this._alertNamePwned(dview, breaches, warning, args);
                                },
                                cancel: () => { // reset name by not registering change
                                    hLogger.info('reverting to previous user name');
                                }
                            });
                        } else { // check level = alert, keep new name but sets an alert
                            this._alertNamePwned(dview, breaches, warning, args);
                        }
                    } else { // not pawned
                        this._alertNamePwned(dview, null, null, args);
                    }
                }).catch(error => {
                    hLogger.error('check pwned name error', error.message);
                });
        } else {
            hibp._alertNamePwned(this, null, null, args);
        }
    }
    /**
     * Displays name and password fieds in the details view depending on thair pawnage status.
     * The status is checked dynamically.
     * @param {DetailsView} dview the detailed view
     */
    displayFields(dview) {
        // check password
        const pwd = dview.model.password ? dview.model.password.getText() : null;
        // hLogger.debug('addfv pwd:>>>', pwd, '<<<');
        if (this.checkPwnedPwd !== HIBPCheckLevel.None && this.elligiblePwd(pwd)) {
            this.sha1(pwd)
                .then(hpwd => {
                    return this.checkPwdPwned(hpwd);
                })
                .then(nb => {
                    // hLogger.debug(pwd, 'pppwand', nb);
                    dview.model.pwdPwned = nb;
                    if (nb) { // pawned
                        const warning = HIBPLocale.hibpPwdWarning.replace('{}', nb);
                        this._alert(dview.passEditView.$el, warning);
                    } else { // not pawned
                        this._passed(dview.passEditView.$el, 'check pwned password passed...');
                    }
                }).catch(error => {
                    hLogger.error('check pwned pwd error', error);
                });
        }
        // check user name
        let name = dview.userEditView.value;
        // hLogger.debug('addfv name:>>>', name, '<<<');
        if (this.elligibleName(name) && this.checkPwnedName !== HIBPCheckLevel.None) {
            this.checkNamePwned(name)
                .then(breaches => {
                    dview.model.namePwned = breaches;
                    if (breaches) { // pawned
                        name = _.escape(name); // breaches already escaped
                        const warning = HIBPLocale.hibpNameWarning.replace('{name}', name).replace('{breaches}', breaches);
                        this._alert(dview.userEditView.$el, warning);
                    } else { // not pawned
                        this._passed(dview.userEditView.$el, 'check pwned user name passed...');
                    }
                }).catch(error => {
                    hLogger.error('displayFields: check pwned name error', error);
                });
        }
    };
    /**
     * Check asynchronously the given entries from the given application model
     * @param {AppModel} app the Application Model
     * @param {Model} entries the entries to check
     */
    checkEntries(app, entries) {
        this._appModel = app;

        hLogger.debug('getEntriesByFilter'); // , 'entries =', entries);
        if (this.checkPwnedList && !this.stopCheckingNames && entries && entries.length) {
            let refresh = false;
            // push all different names and pwds not already in cache to the waiting lists to reduce the number of calls to the HIBP API.
            // the waiting elements will be processed by checkNextWaitingElement
            entries.forEach(item => {
                // hLogger.debug('getEntriesByFilter', 'item=', item.title);
                const name = encodeURIComponent(item.user);
                if (this.elligibleName(item.user)) {
                    if (this._isInCache('_pwnedNamesCache', name)) {
                        const breaches = this._getCache('_pwnedNamesCache', name);
                        refresh = refresh || HIBPUtils.xor(breaches, item.namePwned);
                        item.namePwned = breaches;
                    } else {
                        const fname = this._waitingNames.find(elem => elem.name === name);
                        if (fname) fname.items.push(item);
                        else this._waitingNames.push({ name: name, items: [item] });
                    }
                }
                let pwd = item.password;
                if (pwd) {
                    pwd = pwd.getText();
                    if (this.elligiblePwd(pwd)) {
                        this.sha1(pwd)
                            .then(passwordHash => {
                                passwordHash.toUpperCase();
                                if (this._isInCache('_pwnedPwdsCache', passwordHash)) {
                                    const nb = this._getCache('_pwnedPwdsCache', passwordHash);
                                    refresh = refresh || HIBPUtils.xor(nb, item.pwdPwned);
                                    item.pwdPwned = nb;
                                } else {
                                    const fpwd = this._waitingPwds.find(elem => elem.pwd === pwd);
                                    if (fpwd) fpwd.items.push(item);
                                    else this._waitingPwds.push({ pwd: pwd, items: [item] });
                                }
                            });
                    }
                };
            });
            refresh && this._appModel.refresh();
        }
    }
    /**
     * Check waiting elements (name and pwd) until first one not already in cache.
     */
    checkNextWaitingElems() {
        let elem = null;
        let inCache;
        if (this._waitingNames.length) {
            inCache = true; // true to take at least one elem
            while (inCache && (elem = this._waitingNames.shift())) {
                inCache = this._isInCache('_pwnedNamesCache', elem.name);
                this.checkNamePwned(elem.name)
                    .then(breaches => {
                        let refresh = false;
                        elem.items.forEach(item => {
                            refresh = refresh || HIBPUtils.xor(breaches, item.namePwned);
                            item.namePwned = breaches;
                        });
                        refresh && this._appModel.refresh();
                    })
                    .catch(err => {
                        hLogger.error('error in checking name', elem.name, 'in checkNextWaitingElems', err);
                    });
            }
        }
        if (this._waitingPwds.length) {
            inCache = true;
            while (inCache && (elem = this._waitingPwds.shift())) {
                inCache = this._isInCache('_pwnedPwdsCache', elem.pwd);
                this.sha1(elem.pwd)
                    .then(hpwd => {
                        return this.checkPwdPwned(hpwd);
                    })
                    .then(nb => {
                        let refresh = false;
                        elem.items.forEach(item => {
                            refresh = refresh || HIBPUtils.xor(nb, item.pwdPwned);
                            item.pwdPwned = nb;
                        });
                        refresh && this._appModel.refresh();
                    })
                    .catch(err => {
                        hLogger.error('error in checking pwd', elem.pwd, 'in checkNextWaitingElems', err);
                    });
            }
        }
    }
};

/** the HIBP singleton
 * @type {HIBP}
 */
const hibp = new HIBP();

/**
 * Replaces the fiedChanged function of DetailsView to add checks on user names and passwords
 * @param {Event} e the event that triggered the change
 */
DetailsView.prototype.fieldChanged = function (e) {
    if (e.field) {
        // hLogger.debug('field changed', e);
        // first check password
        if (e.field === '$Password' && hibp.checkPwnedPwd !== HIBPCheckLevel.None && this.passEditView.value) {
            hibp.handlePasswordChange(this, e.val, arguments);
            // second, check user name
        } else if (e.field === '$UserName' && hibp.checkPwnedName !== HIBPCheckLevel.None) {
            hibp.handleNameChange(this, e.val, arguments);
        }
    } else { // not name, not password
        detailsViewFieldChanged.apply(this, arguments);
    }
};

/**
 * Replaces initial addFieldViews function in DetailsView
 * Allows showing pawned fields when displaying entry details
 */
DetailsView.prototype.addFieldViews = function () {
    // call initial function
    detailsViewAddFieldViews.apply(this, arguments);
    hibp.displayFields(this);
};

/**
 * Replaces initial render function in ListView
 */
ListView.prototype.render = function () {
    listViewRender.apply(this, arguments);
    hLogger.debug('rendering list in hibp');
    this.items.filter(item => item.namePwned || item.pwdPwned).forEach(item => {
        // hLogger.debug('list pwned item "' + item.title + '"');
        const itemEl = document.getElementById(item.id);
        itemEl && itemEl.classList.add('hibp-pwned');
    });
};

/**
 * Replaces initial getEntriesByFilter in AppModel
 * Check all entries to see if they are pawned
 * @param {Filter} filter
 */
AppModel.prototype.getEntriesByFilter = function (filter) {
    const entries = appModelGetEntriesByFilter.apply(this, arguments);
    hibp.checkEntries(this, entries);
    return entries;
};

/**
 * @return settings of the plugin
 */
module.exports.getSettings = function () {
    const options = [
        { value: HIBPCheckLevel.None, label: HIBPLocale.hibpCheckLevelNone },
        { value: HIBPCheckLevel.Alert, label: HIBPLocale.hibpCheckLevelAlert },
        { value: HIBPCheckLevel.AskMe, label: HIBPLocale.hibpCheckLevelAskMe }
    ];
    return [
        {
            name: 'checkPwnedPwd',
            label: HIBPLocale.hibpCheckPwnedPwd,
            type: 'select',
            options: options,
            value: hibp.checkPwnedPwd
        }, {
            name: 'checkPwnedName',
            label: HIBPLocale.hibpCheckPwnedName,
            type: 'select',
            options: options,
            value: hibp.checkPwnedName
        }, {
            name: 'checkPwnedList',
            label: HIBPLocale.hibpCheckOnList,
            type: 'checkbox',
            value: hibp.checkPwnedList
        }, {
            name: 'debugMode',
            label: 'debug mode',
            type: 'checkbox',
            value: false
        }
    ];
};

/**
 * Take settings changes into account
 * @param {Settings array} changes
 */
module.exports.setSettings = function (changes) {
    for (const field in changes) {
        const ccfield = field.substr(0, 1).toLowerCase() + field.substring(1);
        if (ccfield === 'debugMode') {
            hLogger.setLevel(changes[field] ? HLoggerDebug : HLoggerRegular);
        } else {
            hibp[ccfield] = changes[field];
        }
    }
    hLogger.debug('SetSettings', hibp);
};

/**
 * Reset all changes when the plugin is uninstalled
 */
module.exports.uninstall = function () {
    DetailsView.prototype.fieldChanged = detailsViewFieldChanged;
    DetailsView.prototype.addFieldViews = detailsViewAddFieldViews;
    ListView.prototype.render = listViewRender;
    AppModel.prototype.getEntriesByFilter = appModelGetEntriesByFilter;
};
