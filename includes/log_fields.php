<?php
/* Métadonnées pour le laboratoire; masquage des champs usuels de secrets. */
function minisoc_clean_log_value($value, int $depth = 0) {
    if ($depth > 4) return '[depth-limit]';
    if (is_array($value)) {
        $clean = [];
        foreach (array_slice($value, 0, 100, true) as $key => $item) {
            $secret = in_array(strtolower((string)$key), ['password','passwd','pass','pwd','token',
                'access_token','refresh_token','secret','api_key','apikey','authorization',
                'cookie','session','sessionid','csrf','csrf_token'], true);
            $clean[substr((string)$key,0,80)] = $secret ? '[REDACTED]' : minisoc_clean_log_value($item,$depth+1);
        }
        return $clean;
    }
    return substr((string)$value,0,2048);
}
function minisoc_log_params(array $get, array $post): string {
    $all=[];
    foreach (['GET'=>$get,'POST'=>$post] as $prefix=>$params)
        foreach (minisoc_clean_log_value($params) as $key=>$value) $all[$prefix.'_'.$key]=$value;
    return json_encode($all,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE);
}
