import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Learn',
    Svg: require('@site/static/img/learn.svg').default,
    description: (
      <>
        Interesting stuff.
      </>
    ),
  },
  {
    title: 'Play',
    Svg: require('@site/static/img/play.svg').default,
    description: (
      <>
        And have fun!
      </>
    ),
  },
  {
    title: 'Document',
    Svg: require('@site/static/img/document.svg').default,
    description: (
      <>
        To consolidate.
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
