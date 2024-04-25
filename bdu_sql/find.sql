SELECT
    public.sbom_components."raw",
    public."BDU"."raw"
FROM
    public.sbom_components
    INNER JOIN public.components ON public.sbom_components.name = public.components.name
    INNER JOIN public."BDU" ON public.components.id_bdu = public."BDU".id
WHERE
    public.sbom_components."SBOM_raw" = id;