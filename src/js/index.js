(function() {

    // mnemonics is populated as required by getLanguage
    var mnemonics = { "english": new Mnemonic("english") };
    var mnemonic = mnemonics["english"];

    var shamir39 = new Shamir39();

    var phraseChangeTimeoutEvent = null;

    var DOM = {};
    DOM.splitPhrase = $("#split-phrase");
    DOM.parameterM = $(".parameter-m");
    DOM.parameterN = $(".parameter-n");
    DOM.splitParts = $("#split-parts");
    DOM.generatedStrength = $(".generate-container .strength");
    DOM.combineParts = $("#combine-parts");
    DOM.combinePhrase = $("#combine-phrase");
    DOM.generateContainer = $(".generate-container");
    DOM.generate = $(".generate");
    DOM.languages = $(".languages a");
    DOM.feedback = $(".feedback");
    DOM.testButton = $(".btn-test");

    function init() {
        // Events
        DOM.splitPhrase.on("input", delayedPhraseChanged);
        DOM.parameterM.on("input", delayedPhraseChanged);
        DOM.parameterN.on("input", delayedPhraseChanged);
        DOM.generate.on("click", generateClicked);
        DOM.languages.on("click", languageChanged);
        DOM.combineParts.on("input", combinePartsChanged);
        DOM.testButton.on("click", testShares);
        disableForms();
        clearDisplay();
    }

    // Event handlers

    function delayedPhraseChanged() {
        hideValidationError();
        if (phraseChangeTimeoutEvent != null) {
            clearTimeout(phraseChangeTimeoutEvent);
        }
        phraseChangeTimeoutEvent = setTimeout(phraseChanged, 400);
    }

    function phraseChanged() {
        showPending();
        setMnemonicLanguage();
        // Get the mnemonic phrase
        var phrase = DOM.splitPhrase.val();
        var errorText = findPhraseErrors(phrase);
        if (errorText) {
            showValidationError(errorText);
            return;
        }
        // Calculate and display
        showSplitPhrase(phrase);
        hidePending();
    }

    function generateClicked() {
        clearDisplay();
        setTimeout(function() {
            setMnemonicLanguage();
            var phrase = generateRandomPhrase();
            if (!phrase) {
                return;
            }
            phraseChanged();
        }, 50);
    }

    function languageChanged() {
        setTimeout(function() {
            setMnemonicLanguage();
            var oldPhrase = DOM.splitPhrase.val();
            if (oldPhrase.length > 0) {
                var newPhrase = convertPhraseToNewLanguage(oldPhrase);
                DOM.splitPhrase.val(newPhrase);
                phraseChanged();
            }
            else {
                DOM.generate.trigger("click");
            }
        }, 50);
    }

    function combinePartsChanged() {
        var partsStr = DOM.combineParts.val();
        showCombinedPhrase(partsStr);
    }

    // Private methods

    function showSplitPhrase(phrase) {
        var words = phraseToWordArray(phrase);
        var m = parseInt(DOM.parameterM.val());
        var n = parseInt(DOM.parameterN.val());
        var language = getLanguage(phrase);
        var wordlist = WORDLISTS[language];
        var parts = shamir39.split(words, wordlist, m, n);
        if ("error" in parts) {
            DOM.splitParts.val(parts.error);
            DOM.testButton.addClass('disabled');
            return;
        }
        DOM.testButton.removeClass('disabled');
        // Convert mnemonics into phrases
        var mnemonics = parts.mnemonics;
        for (var i=0; i<mnemonics.length; i++) {
            mnemonics[i] = wordArrayToPhrase(mnemonics[i]);
        }
        var partsStr = mnemonics.join("\n\n");
        DOM.splitParts.val(partsStr);
    }

    function stringToParts(partsStr) {
        var partsDirty = partsStr.split("\n");
        var parts = [];
        for (var i=0; i<partsDirty.length; i++) {
            var part = partsDirty[i];
            part = part.trim();
            if (part.length > 0) {
                parts.push(part);
            }
        }

        return parts;
    }

    function partsToWordArrays(parts) {
        var mnemonics = [];
        for (var i=0; i<parts.length; i++) {
            var part = parts[i];
            var mnemonic = phraseToWordArray(part);
            mnemonics.push(mnemonic);
        }
        return mnemonics;
    }

    function showCombinedPhrase(partsStr) {
        var parts = stringToParts(partsStr);
        var mnemonics = partsToWordArrays(parts);

        // combine the phrases into the original mnemonic
        var language = getLanguage(parts[0]);
        var wordlist = WORDLISTS[language];
        var words = shamir39.combine(mnemonics, wordlist);
        if ("error" in words) {
            DOM.combinePhrase.val(words.error);
            return;
        }
        var phrase = wordArrayToPhrase(words.mnemonic);
        DOM.combinePhrase.val(phrase);
    }

    function generateRandomPhrase() {
        if (!hasStrongRandom()) {
            var errorText = "This browser does not support strong randomness";
            showValidationError(errorText);
            return;
        }
        var numWords = parseInt(DOM.generatedStrength.val());
        var strength = numWords / 3 * 32;
        var words = mnemonic.generate(strength);
        DOM.splitPhrase.val(words);
        return words;
    }

    function showPending() {
        DOM.feedback
            .text("Calculating...")
            .show();
    }

    function hidePending() {
        DOM.feedback
            .text("")
            .hide();
    }

    function showValidationError(errorText) {
        DOM.feedback
            .text(errorText)
            .show();
    }

    function hideValidationError() {
        DOM.feedback
            .text("")
            .hide();
    }

    function findPhraseErrors(phrase) {
        // Preprocess the words
        phrase = mnemonic.normalizeString(phrase);
        var words = phraseToWordArray(phrase);
        // Detect blank phrase
        if (words.length == 0) {
            return "Blank mnemonic";
        }
        // Check each word
        for (var i=0; i<words.length; i++) {
            var word = words[i];
            var language = getLanguage(phrase);
            if (WORDLISTS[language].indexOf(word) == -1) {
                console.log("Finding closest match to " + word);
                var nearestWord = findNearestWord(word);
                return word + " not in wordlist, did you mean " + nearestWord + "?";
            }
        }
        // Check the words are valid
        var properPhrase = wordArrayToPhrase(words);
        var isValid = mnemonic.check(properPhrase);
        if (!isValid) {
            return "Invalid mnemonic";
        }
        return false;
    }

    function hasStrongRandom() {
        return 'crypto' in window && window['crypto'] !== null;
    }

    function disableForms() {
        $("form").on("submit", function(e) {
            e.preventDefault();
        });
    }

    function findNearestWord(word) {
        var language = getLanguage(word);
        var words = WORDLISTS[language];
        var minDistance = 99;
        var closestWord = words[0];
        for (var i=0; i<words.length; i++) {
            var comparedTo = words[i];
            if (comparedTo.indexOf(word) == 0) {
                return comparedTo;
            }
            var distance = Levenshtein.get(word, comparedTo);
            if (distance < minDistance) {
                closestWord = comparedTo;
                minDistance = distance;
            }
        }
        return closestWord;
    }

    function clearDisplay() {
        // TODO clear split parts
        hideValidationError();
    }

    function hidePending() {
        DOM.feedback
            .text("")
            .hide();
    }

    function getLanguage(phrase) {
        var defaultLanguage = "english";
        // Try to get from existing phrase
        var language = getLanguageFromPhrase(phrase);
        // Try to get from url if not from phrase
        if (language.length == 0) {
            language = getLanguageFromUrl();
        }
        // Default to English if no other option
        if (language.length == 0) {
            language = defaultLanguage;
        }
        return language;
    }

    function getLanguageFromPhrase(phrase) {
        // Check if how many words from existing phrase match a language.
        var language = "";
        if (!phrase) {
            phrase = DOM.splitPhrase.val();
        }
        if (phrase.length > 0) {
            var words = phraseToWordArray(phrase);
            var languageMatches = {};
            for (l in WORDLISTS) {
                // Track how many words match in this language
                languageMatches[l] = 0;
                for (var i=0; i<words.length; i++) {
                    var wordInLanguage = WORDLISTS[l].indexOf(words[i]) > -1;
                    if (wordInLanguage) {
                        languageMatches[l]++;
                    }
                }
                // Find languages with most word matches.
                // This is made difficult due to commonalities between Chinese
                // simplified vs traditional.
                var mostMatches = 0;
                var mostMatchedLanguages = [];
                for (var l in languageMatches) {
                    var numMatches = languageMatches[l];
                    if (numMatches > mostMatches) {
                        mostMatches = numMatches;
                        mostMatchedLanguages = [l];
                    }
                    else if (numMatches == mostMatches) {
                        mostMatchedLanguages.push(l);
                    }
                }
            }
            if (mostMatchedLanguages.length > 0) {
                // Use first language and warn if multiple detected
                language = mostMatchedLanguages[0];
                if (mostMatchedLanguages.length > 1) {
                    console.warn("Multiple possible languages");
                    console.warn(mostMatchedLanguages);
                }
            }
        }
        return language;
    }

    function getLanguageFromUrl() {
        for (var language in WORDLISTS) {
            if (window.location.hash.indexOf(language) > -1) {
                return language;
            }
        }
        return "";
    }

    function setMnemonicLanguage() {
        var language = getLanguage();
        // Load the bip39 mnemonic generator for this language if required
        if (!(language in mnemonics)) {
            mnemonics[language] = new Mnemonic(language);
        }
        mnemonic = mnemonics[language];
    }

    function convertPhraseToNewLanguage(oldPhrase) {
        var oldLanguage = getLanguageFromPhrase(oldPhrase);
        var newLanguage = getLanguageFromUrl();
        var oldWords = phraseToWordArray(oldPhrase);
        var newWords = [];
        for (var i=0; i<oldWords.length; i++) {
            var oldWord = oldWords[i];
            var index = WORDLISTS[oldLanguage].indexOf(oldWord);
            var newWord = WORDLISTS[newLanguage][index];
            newWords.push(newWord);
        }
        newPhrase = wordArrayToPhrase(newWords);
        return newPhrase;
    }

    // TODO look at jsbip39 - mnemonic.splitWords
    function phraseToWordArray(phrase) {
        var words = phrase.split(/\s/g);
        var noBlanks = [];
        for (var i=0; i<words.length; i++) {
            var word = words[i];
            if (word.length > 0) {
                noBlanks.push(word);
            }
        }
        return noBlanks;
    }

    // TODO look at jsbip39 - mnemonic.joinWords
    function wordArrayToPhrase(words) {
        var phrase = words.join(" ");
        var language = getLanguageFromPhrase(phrase);
        if (language == "japanese") {
            phrase = words.join("\u3000");
        }
        return phrase;
    }

    function testShares() {
        showValidationError('Testing, please wait...')
        setTimeout(_testShares, 50);
    }

    function _testShares() {
        var partsStr = DOM.splitParts.val();
        var parts = stringToParts(partsStr);
        var mnemonics = partsToWordArrays(parts);

        var m = parseInt(DOM.parameterM.val());
        var n = parseInt(DOM.parameterN.val());
        var language = getLanguage(parts[0]);
        var wordlist = WORDLISTS[language];

        // parse original phrase and re-convert to string for ease of comparison
        var originalPhrase = phraseToWordArray(DOM.splitPhrase.val()).join(' ');

        var ok = true;
        var numSolutions = 0;
        shamir39.testCombine(mnemonics, wordlist, function(usedMnemonics, solution) {
            if (usedMnemonics.length < m) {
                if (solution.error === undefined) {
                    ok = false;
                    console.log('I should get an error by using only ' +
                        usedMnemonics.length + ' mnemonics, but got', solution)
                }
                /* else OK - didn't find a solution when it wasn't expected */
            }
            else {
                if (solution.mnemonic === undefined) {
                    ok = false;
                    console.log('I did not get a mnemonic but an error:', solution);
                }
                else if (solution.mnemonic.join(' ') !== originalPhrase) {
                    ok = false;
                    console.log('I did not get the original mnemonic but', solution);
                }
                else { /* OK - found a solution and was valid */
                    numSolutions++;
                }
            }
        });

        function factorial(x) {
            var result = (x == 0 ? 1 : x);
            while (--x > 1) {
                result *= x;
            }
            return result;
        }
        var desiredSolutions = 0;
        for (var i=m; i<=n; i++) { /* combinations of m..n elements out of n */
            desiredSolutions += factorial(n) / (factorial(i)*factorial(n-i));
        }

        console.log('I expected to find', desiredSolutions, 'solutions, found', numSolutions);
        if (numSolutions != desiredSolutions) {
            ok = false;
        }

        showValidationError(ok ? 'Test Succeeded!' : 'Test Failed');
    }

    init();

})();
