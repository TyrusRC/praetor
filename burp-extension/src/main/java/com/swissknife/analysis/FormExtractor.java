package com.swissknife.analysis;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extract HTML forms and their input fields from response body.
 */
public final class FormExtractor {

    private FormExtractor() {}

    private static final Pattern FORM_PATTERN = Pattern.compile(
        "<form[^>]*>(.*?)</form>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );
    private static final Pattern ATTR_PATTERN = Pattern.compile(
        "(action|method|enctype|id|name)\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern INPUT_PATTERN = Pattern.compile(
        "<(input|textarea|select)[^>]*>", Pattern.CASE_INSENSITIVE
    );
    private static final Pattern INPUT_ATTR_PATTERN = Pattern.compile(
        "(type|name|value|id|placeholder|required|hidden)\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE
    );

    public static Map<String, Object> extract(String html) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> forms = new ArrayList<>();

        Matcher formMatcher = FORM_PATTERN.matcher(html);
        while (formMatcher.find()) {
            String formTag = html.substring(formMatcher.start(), html.indexOf('>', formMatcher.start()) + 1);
            String formBody = formMatcher.group(1);

            Map<String, Object> form = new LinkedHashMap<>();

            // Extract form attributes
            Matcher attrMatcher = ATTR_PATTERN.matcher(formTag);
            while (attrMatcher.find()) {
                form.put(attrMatcher.group(1).toLowerCase(), attrMatcher.group(2));
            }

            // Extract inputs
            List<Map<String, Object>> inputs = new ArrayList<>();
            Matcher inputMatcher = INPUT_PATTERN.matcher(formBody);
            while (inputMatcher.find()) {
                String inputTag = inputMatcher.group(0);
                Map<String, Object> input = new LinkedHashMap<>();
                input.put("tag", inputMatcher.group(1).toLowerCase());

                Matcher inputAttrMatcher = INPUT_ATTR_PATTERN.matcher(inputTag);
                while (inputAttrMatcher.find()) {
                    input.put(inputAttrMatcher.group(1).toLowerCase(), inputAttrMatcher.group(2));
                }
                inputs.add(input);
            }

            form.put("inputs", inputs);
            forms.add(form);
        }

        result.put("total_forms", forms.size());
        result.put("forms", forms);
        return result;
    }
}
