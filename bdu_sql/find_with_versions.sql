SELECT
    public.sbom_components."raw",
    public."BDU"."raw"
FROM
    public.sbom_components
    INNER JOIN public.components ON public.sbom_components.name = public.components.name
    INNER JOIN public."BDU" ON public.components.id_bdu = public."BDU".id
WHERE
    public.sbom_components."SBOM_raw" = 3
    AND (
        public.sbom_components.version = public.components.only
        OR (
            (
                public.sbom_components.major >= public.components.from_major
                OR (
                    public.sbom_components.major >= public.components.from_major
                    AND public.sbom_components.minor >= public.components.from_minor
                )
                OR (
                    public.sbom_components.major >= public.components.from_major
                    AND public.sbom_components.minor >= public.components.from_minor
                    AND public.sbom_components.patch >= public.components.from_patch
                )
            )
            AND (
                (
                    public.components.inclusive
                    AND (
                        public.sbom_components.major <= public.components.to_major
                        OR (
                            public.sbom_components.major <= public.components.to_major
                            AND public.sbom_components.minor <= public.components.to_minor
                        )
                        OR (
                            public.sbom_components.major <= public.components.to_major
                            AND public.sbom_components.minor <= public.components.to_minor
                            AND public.sbom_components.patch <= public.components.to_patch
                        )
                    )
                )
                OR (
                    NOT public.components.inclusive
                    AND (
                        public.sbom_components.major < public.components.to_major
                        OR (
                            public.sbom_components.major < public.components.to_major
                            AND public.sbom_components.minor < public.components.to_minor
                        )
                        OR (
                            public.sbom_components.major < public.components.to_major
                            AND public.sbom_components.minor < public.components.to_minor
                            AND public.sbom_components.patch < public.components.to_patch
                        )
                    )
                )
            )
        )
    );